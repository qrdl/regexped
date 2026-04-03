# Regexped CLI Reference

## Configuration File

Regexped is driven by a YAML config file (default: `regexped.yaml` in the current directory).

```yaml
wasm_merge: "wasm-merge"   # path to wasm-merge binary; defaults to wasm-merge in $PATH
output:   "merged.wasm"    # output path for the merge command; overridable with --output
wasm_file: "regexps.wasm"  # output path for the compile command; overridable with --output
import_module: "mymod"     # WASM module name used by wasm-merge and Rust FFI
stub_file: "src/stubs.rs"  # stub output file; extension determines type: .rs, .js, .ts
stub_type: "rust"          # optional; overrides extension-based type inference: rust, js, ts
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

## Commands

All commands validate their required options and config fields before doing any work. Invalid or missing values are reported immediately.

### `generate` — Generate language stubs

```
regexped generate [--config=<file>] [--output=<file>|-]
```

Generates a stub file (Rust, JS, or TypeScript) from the config. The stub type is determined by:

1. `stub_type` field in YAML (`rust`, `js`, `ts`)
2. Extension of `stub_file` in YAML (`.rs` → rust, `.js` → js, `.ts` → ts)
3. Error if neither resolves to a known type

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
| `import_module` | Required for Rust stubs; used as `pub mod` block name |

#### Rust stubs

All entries are wrapped in a single `pub mod <import_module> { }` block.

| Config field | Generated function | Return type |
|---|---|---|
| `match_func` | `<func>(input)` | `Option<usize>` |
| `find_func` | `<func>(input)` | `FindIter` — yields `(usize, usize)` per match |
| `groups_func` | `<func>(input)` | `GroupsIter` — yields `Vec<Option<(usize, usize)>>` per match |
| `named_groups_func` | `<func>(input)` | `NamedGroupsIter` — yields `HashMap<&'static str, (usize, usize)>` per match |

See [rust-api.md](rust-api.md) for full usage examples.

#### JS stubs

Generates a single ES module with top-level `await`. Requires `output` (merged WASM path) in config.

| Config field | Generated JS export | Returns |
|---|---|---|
| `match_func` | `function <func>(input)` | `boolean` — true if full input matches |
| `find_func` | `function* <func>(input)` | generator yielding `[start, end]` per match |
| `groups_func` | `function* <func>(input)` | generator yielding `Array<[start,end]\|null>` per match |
| `named_groups_func` | `function* <func>(input)` | generator yielding `Object` (name→`[start,end]`) per match |

#### TS stubs

Same as JS stubs but with TypeScript type annotations. Compatible with Node.js (via `tsx`), Deno, and browsers.

---

### `compile` — Compile patterns to WASM

```
regexped compile [--config=<file>] [--main=<file>] [--output=<file>|-]
```

Compiles each regex pattern to a single WASM module containing all compiled functions.

If `--main` is given, reads the host WASM to determine where to place DFA/TDFA tables in memory (above the host's data). If omitted, `rustTop=0` is assumed (suitable for JS/browser/CF Worker deployments).

**Flags:**

| Flag | Default | Description |
|---|---|---|
| `--config` | `regexped.yaml` | YAML config file |
| `--main` | — | Pre-built host WASM file for memory layout (optional) |
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
regexped merge [--config=<file>] (--main=<file>|--dummy-main) [--output=<file>|-] <regex1.wasm> ...
```

Patches the main module's memory section to fit all regex tables, then calls `wasm-merge` to produce a single combined binary.

`--main` and `--dummy-main` are mutually exclusive; exactly one is required:
- `--main=<file>` — use the specified host WASM as the main module (Rust deployments)
- `--dummy-main` — use the built-in memory-only dummy main (JS/browser/CF Worker deployments)

**Flags:**

| Flag | Default | Description |
|---|---|---|
| `--config` | `regexped.yaml` | YAML config file |
| `--main` | — | Host main WASM file |
| `--dummy-main` | — | Use built-in dummy main |
| `--output`, `-o` | config `output` | Output WASM file; `-` writes to stdout |

**Positional arguments:** one or more regex WASM files (at least one required).

**Required config fields:**

| Field | Notes |
|---|---|
| `output` | Required unless `--output` is given |
| `wasm_merge` | Optional; path to wasm-merge binary; defaults to `wasm-merge` in $PATH |
| `import_module` | Optional; module name passed to wasm-merge; defaults to the basename of the regex WASM |

---

## Typical workflows

### Rust deployment

```bash
# 1. Generate Rust stubs
regexped generate --config=regexped.yaml

# 2. Build your Rust project to WASM (produces main.wasm)
cargo build --target wasm32-wasip1 --release

# 3. Compile regex patterns to WASM
regexped compile --config=regexped.yaml --main=target/wasm32-wasip1/release/app.wasm

# 4. Merge everything into a single binary
regexped merge --config=regexped.yaml --main=target/wasm32-wasip1/release/app.wasm pattern.wasm
```

### JS / Browser / Cloudflare Worker deployment

```bash
# 1. Compile regex patterns to WASM (no host runtime needed)
regexped compile --config=regexped.yaml

# 2. Merge with built-in dummy main
regexped merge --config=regexped.yaml --dummy-main regexps.wasm

# 3. Generate JS/TS stub
regexped generate --config=regexped.yaml
```


```yaml
wasm_merge: "wasm-merge"   # path to wasm-merge binary; defaults to wasm-merge in $PATH
output:   "merged.wasm"    # output path for the merge command; overridable with -o/--output
wasm_dir: "."              # default output directory for compiled WASM files; overridable with -d/--out-dir
stub_file: "src/stubs.rs"  # default stub output file for all entries (Rust or JS); per-entry overrides
max_dfa_states: 1024       # optional; max DFA/TDFA states before falling back to Backtracking (default 1024)
max_tdfa_regs:  32         # optional; max TDFA registers before falling back to Backtracking (default 32)

regexes:
  - wasm_file:        "url.wasm"     # output WASM file for this pattern
    import_module:    "url"          # WASM import module name (used by wasm-merge and Rust FFI)
    stub_file:        "src/url.rs"   # per-entry override; if absent, uses top-level stub_file
    pattern:          'https?://...' # RE2 regex pattern

    # One or more func fields — only those set are compiled and stubbed.
    # The func name becomes both the WASM export name and the generated function name.
    # An entry with only 'pattern' is valid; no WASM or stub is generated for it.
    match_func:        "url_match"         # anchored match
    find_func:         "url_find"          # non-anchored find
    groups_func:       "url_groups"        # anchored match with all capture groups
    named_groups_func: "url_named_groups"  # anchored match with named capture groups
```

When multiple entries share the same stub file, each entry's stubs are wrapped in a
`pub mod <import_module> { }` block (Rust) to prevent FFI name collisions.

All paths in the config file are resolved relative to the config file's directory.

### Engine selection

Setting `groups_func` or `named_groups_func` triggers capture-tracking compilation:
- **TDFA engine** — used when the pattern has no non-greedy quantifiers, no line anchors, no word boundaries, and no ambiguous alternations (Laurikari’s tagged DFA, O(n))
- **Backtracking engine** — used automatically as a fallback for patterns that are not TDFA-eligible (e.g. `(a|ab)`, `(a*)(a*)`)  

Setting only `match_func` and/or `find_func` uses the **DFA engine**. Capture groups are stripped from the pattern before compilation. If the DFA exceeds `max_dfa_states` states, the **Backtracking engine** is used instead (no captures, same match/find semantics).

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

## Commands

### `generate` — Generate stubs or dummy main module

`--rust`, `--js`, and `--dummy_main` are mutually exclusive.

#### `--rust` — Generate Rust language stubs

```
regexped generate [--config=<file>] [--out-dir=<dir>] [-d <dir>] --rust
```

Generates Rust stub files. Entries sharing the top-level `stub_file` are collected into one file with `pub mod <import_module>` blocks; entries with a per-entry `stub_file` go to their own file. Output path: `<out-dir>/<stub_file>` (include any subdirectory in the `stub_file` value, e.g. `src/stubs.rs`).

| Config field | Generated function | Return type |
|---|---|---|
| `match_func` | `<func>(input)` | `Option<usize>` |
| `find_func` | `<func>(input)` | `FindIter` — yields `(usize, usize)` per match |
| `groups_func` | `<func>(input)` | `GroupsIter` — yields `Vec<Option<(usize, usize)>>` per match |
| `named_groups_func` | `<func>(input)` | `NamedGroupsIter` — yields `HashMap<&'static str, (usize, usize)>` per match |

See [rust-api.md](rust-api.md) for full usage examples.

**Flags:**

| Flag | Default | Description |
|---|---|---|
| `--config` | `regexped.yaml` | YAML config file |
| `--out-dir`, `-d` | `.` | Output directory |
| `--rust` | — | Generate Rust stubs |

#### `--js` — Generate a JS ES module stub

```
regexped generate [--config=<file>] [--out-dir=<dir>] [-d <dir>] --js
```

Generates a single ES module that loads the merged WASM (`output` field) and exports wrapper functions for every entry. Output path: `<out-dir>/<stub_file>`.

Requires `output` and `stub_file` to be set in the config.

| Config field | Generated JS export | Returns |
|---|---|---|
| `match_func` | `function <func>(input)` | `boolean` — true if full input matches |
| `find_func` | `function* <func>(input)` | generator yielding `[start, end]` per match |
| `groups_func` | `function* <func>(input)` | generator yielding `Array<[start,end]\|null>` per match |
| `named_groups_func` | `function* <func>(input)` | generator yielding `Object` (name→`[start,end]`) per match |

The generated module uses top-level `await` and is suitable for `<script type="module">` or ESM imports. Input can be a `string` or `Uint8Array`.

**Flags:**

| Flag | Default | Description |
|---|---|---|
| `--config` | `regexped.yaml` | YAML config file |
| `--out-dir`, `-d` | `.` | Output directory |
| `--js` | — | Generate JS ES module stub |

---

#### `--dummy_main` — Generate a minimal main WASM module

```
regexped generate [--out-dir=<dir>] [-d <dir>] --dummy_main
```

Writes `main.wasm` to `<out-dir>`. The generated module exports 2 pages of memory and has no code or data. Use it as:

- `--wasm-input` for the `compile` command when there is no Rust main module (e.g. browser deployments)
- The `main` module in a `wasm-merge` invocation

No config file is required.

**Flags:**

| Flag | Default | Description |
|---|---|---|
| `--out-dir`, `-d` | `.` | Output directory for `main.wasm` |
| `--dummy_main` | — | Generate dummy main WASM |

---

### `compile` — Compile patterns to WASM

```
regexped compile [--config=<file>] --wasm-input=<main.wasm> [--out-dir=<dir>] [-d <dir>]
```

Reads the pre-built main WASM module to determine where in memory to place DFA/TDFA tables, then compiles each regex to a standalone WASM module.

**Flags:**

| Flag | Default | Description |
|---|---|---|
| `--config` | `regexped.yaml` | YAML config file |
| `--wasm-input` | — | Pre-built main WASM file **(required)** |
| `--out-dir`, `-d` | config `wasm_dir`, then `.` | Output directory for `.wasm` files |

Entries with no `_func` fields are silently skipped — no WASM file is written.

---

### `merge` — Merge WASM modules

```
regexped merge [--config=<file>] [--output=<out.wasm>] [-o <out.wasm>] <main.wasm> [regex.wasm ...]
```

Patches the main module's memory section to fit all regex tables, then calls `wasm-merge` to produce a single combined binary.

**Flags:**

| Flag | Default | Description |
|---|---|---|
| `--config` | `regexped.yaml` | YAML config file |
| `--output`, `-o` | config `output` | Output WASM file |

**Positional arguments:** `<main.wasm>` followed by one or more regex WASM files (in any order).

---

## Typical workflow

```bash
# 1. Generate Rust stubs
regexped generate --config=regexped.yaml --rust

# 2. Build your Rust project to WASM (produces main.wasm)
cargo build --target wasm32-wasip1 --release

# 3. Compile regex patterns to WASM
regexped compile --config=regexped.yaml --wasm-input=target/wasm32-wasip1/release/app.wasm

# 4. Merge everything into a single binary
regexped merge --config=regexped.yaml target/wasm32-wasip1/release/app.wasm pattern1.wasm pattern2.wasm
```

See [`examples/`](../examples/) for complete self-contained projects with Makefiles.
