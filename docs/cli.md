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

regexps:
  - pattern: 'https?://...' # RE2 regexp pattern
    name: "my_pattern"      # required when referenced by sets: patterns list

    # One or more func fields — only those set are compiled and stubbed.
    # The func name becomes both the WASM export name and the generated function name.
    # An entry with only 'pattern' is valid; no code is generated for it.
    match_func:        "url_match"         # anchored match
    find_func:         "url_find"          # non-anchored find
    groups_func:       "url_groups"        # anchored match with all capture groups
    named_groups_func: "url_named_groups"  # anchored match with named capture groups

    hints: [prefer-match, batch-find]   # optional; see "hints:" below

sets:
  - name: "my_set"             # unique set name
    find_all: "scan_all"       # non-anchored: all matches, streamed in batches
    find_any: "scan_first"     # non-anchored: first match only (optional)
    match: "validate"          # anchored at position 0 (optional)
    emit_name_map: true        # emit patternName(id) lookup helper in stubs
    patterns: all              # "all" or list of name: values from regexps:
    hints: [prefer-no-match]   # optional; per-set default; "batch-find" is not valid here, see below
```

All paths in the config file are resolved relative to the config file's directory.

### Export-name rules

Every `match_func`, `find_func`, `groups_func` and `named_groups_func` value, and every
set's `find_any`, `find_all` and `match` value, becomes both a WASM export name and a
function name in the generated stub. Because they are written verbatim into generated
source, they are validated when the config is loaded, before any compile or generate work
runs. A violation is a hard error: nothing is written and the exit status is non-zero.

- **Shape** — must match `^[A-Za-z_][A-Za-z0-9_]*$`. ASCII only, no leading digit. This is
  stricter than Rust, Go, JS and TS individually allow (all four accept some non-ASCII
  identifiers), so that one config is portable across every `stub_type`.
- **Reserved words** — the name must not be a reserved word in *any* of the six stub
  languages (Rust, Go, C, JavaScript, TypeScript, AssemblyScript), regardless of which
  `stub_type` is configured. The union is used so that changing `stub_type` cannot turn a
  working config into a compile error in the caller's project. Notably this rejects
  `match` (a Rust keyword), `find` and `groups` are fine.
- Contextual keywords that are legal identifiers in their own language — TypeScript's
  `type`, `from`, `of`, `get`, `set`, `string`, `number`, or Go's predeclared `len`/`cap` —
  are **not** rejected.
- **Not** covered: `regexps[].name` and `sets[].name`. Those are selection keys only, and
  reach generated code as quoted string literals rather than identifiers, so reserved
  words and punctuation are fine there.

All offending names are reported in a single pass rather than one per run.

Suffix `_batch` is separately reserved for the compiler-synthesized batch export (see
`hints: [batch-find]` below), and export names must be unique across all `regexps:` and
`sets:` entries.

### Engine selection

Setting `groups_func` or `named_groups_func` triggers capture-tracking compilation:
- **TDFA engine** — used when the pattern has no non-greedy quantifiers, no line anchors, no word boundaries, and no ambiguous alternations (Laurikari's tagged DFA, O(n))
- **Backtracking engine** — used automatically as a fallback for patterns that are not TDFA-eligible (e.g. `(a|ab)`, `(a*)(a*)`)

Setting only `match_func` and/or `find_func` uses the **DFA engine**. Capture groups are stripped from the pattern before compilation.

See [engines.md](engines.md) for full details on engine selection and capabilities.

### `hints:` — LikelyMode and batch-find compile hints

Both `regexps:` entries and `sets:` entries accept an optional `hints:` list.
Three values are recognised; `batch-find` is independent of the other two and
may be combined with either (or neither) — the "mutually exclusive" rule only
ever applies between `prefer-match` and `prefer-no-match`:

- **`prefer-match`** — biases the compiler's code-shape choice for fast-accept.
- **`prefer-no-match`** — biases for fast-reject. Mutually exclusive with
  `prefer-match`.
- **`batch-find`** — requests a `<func>_batch` WASM export for this pattern's
  `find_func` and/or `groups_func` (see below). **Valid only on `regexps:`
  entries** — it is a load-time error on a `sets:` entry (sets have their own
  `find_all` batching via `batch_size`, a separate mechanism).

An absent or empty `hints:` list keeps the default (`LikelyNeutral`, no batch
export). The `prefer-match`/`prefer-no-match` choice never affects match
correctness — only which optimisation path is emitted.

A pattern's own `prefer-match`/`prefer-no-match` takes precedence over its
enclosing set's `hints:` (and a set's own suffix-body compilation falls back
to its `hints:` when a member pattern doesn't set its own). `batch-find` has
no set-level fallback to resolve, since it's rejected on `sets:` entries
outright.

See [prefer-hints.md](prefer-hints.md) for the full `prefer-match`/
`prefer-no-match` mechanism, which pattern shapes benefit, and how to
measure the effect on your own patterns with `tools/pattest`.

#### `batch-find` — batched multi-match export (JS/TS only)

Setting `hints: [batch-find]` on a `regexps:` entry adds a `<func>_batch` WASM
export — `(ptr, len, out_ptr, out_cap, start_pos) → count` — that drains
multiple matches per host call instead of one, for `find_func` and
`groups_func` (`named_groups_func` shares `groups_func`'s batch export when
both are set on the same entry, or gets its own — named after itself — when
`named_groups_func` is the only capture export requested).

**⚠ This hint is effective for the JS and TS generators only.** The generated
JS/TS `find_func`/`groups_func`/`named_groups_func` consumer feature-detects
the `_batch` export at runtime and prefers it automatically — no stub-side
configuration needed, and the same generated stub works unmodified whether or
not `batch-find` was set. **Setting `batch-find` has no effect on stubs
generated for Rust, Go, C, or AssemblyScript** — those generators never look
for a `_batch` export, so the WASM module gains the extra export but nothing
in those stubs ever calls it. This is deliberate, not an oversight: for those
four, the host and the regexp module are fused into one module by
`wasm-merge`, so the `_batch` call would be an ordinary intra-module call, not
the JS↔WASM boundary crossing the batching amortises — there is no
projected win to justify the static-import decidability problems it would
introduce. Don't set `batch-find` expecting a Rust/Go/C/AS speedup.

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
| `import_module` | Required for Rust, Go, C, and AS stubs; validated upfront |

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
| `match_func` | `function <func>(input)` | `[number, boolean]` — `[endPos, matched]` |
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

Compiles each regexp pattern to a single WASM module. The output mode is selected automatically based on the config:

- **Standalone** (no `output` field in config) — the module owns its memory, DFA/TDFA tables start at address 0. Load directly in JS/TS without merging.
- **Embedded** (`output` field present) — the module imports memory from a `"main"` host module. Use `regexped merge` to combine with a Rust/Go/C host binary.

**Flags:**

| Flag | Default | Description |
|---|---|---|
| `--config` | `regexped.yaml` | YAML config file |
| `--output`, `-o` | config `wasm_file` | Output WASM file; `-` writes to stdout |
| `--diag-json` | (none) | Write set-composition diagnostics as JSON to this path; `-` for stdout |

**Required config fields:**

| Field | Notes |
|---|---|
| `wasm_file` | Required unless `--output` is given |
| `regexps` | One or more patterns to compile |

Entries with no `_func` fields produce no individual exports. If such an
entry is also not referenced by any `sets:` block, it is silently skipped;
otherwise it participates only as a member of the set(s) that select it.

#### `sets:` block — multi-pattern set composition

When the config contains a `sets:` block, `compile` also emits multi-pattern set-match functions. Each set entry produces up to three exported WASM functions.

```yaml
regexps:
  - name: aws_key      # name is required for sets: pattern references
    pattern: 'AKIA[0-9A-Z]{16}'
  - name: github_pat
    pattern: 'ghp_[0-9a-zA-Z]{36}'

sets:
  - name: secret_scanner
    find_all: scan_secrets   # non-anchored: returns all matches with positions
    find_any: scan_first     # non-anchored: returns first match only (optional)
    match: validate_secret   # anchored at position 0 (optional)
    batch_size: 256          # output buffer size (stub-gen knob; default 256)
    emit_name_map: true      # emit pattern_name(id) helper in stubs
    patterns:
      - aws_key              # list of regexps.name values
      - github_pat
      # or: patterns: "all" to include every entry in regexps:
```

| `sets:` field | Required | Description |
|---|---|---|
| `name` | Yes | Unique set name |
| `find_all` | At least one | Export name for non-anchored all-matches function |
| `find_any` | At least one | Export name for non-anchored first-match function |
| `match` | At least one | Export name for anchored match function (position 0) |
| `patterns` | Yes | Either `"all"` or a list of `name:` values from `regexps:` |
| `batch_size` | No | Output buffer hint for stub iterators (default 256) |
| `emit_name_map` | No | Emit `pattern_name(id)` lookup in generated stubs |
| `hints` | No | `[prefer-match]` or `[prefer-no-match]`; per-set LikelyMode default. `batch-find` is rejected here — see [`hints:`](#hints--likelymode-and-batch-find-compile-hints) above |

The `name:` field on `regexps:` entries is required when using `patterns: [list]`; optional with `patterns: "all"`.

See [sets.md](sets.md) for full pipeline details and output tuple formats.

---

### `merge` — Merge WASM modules

```
regexped [--debug] merge [--config=<file>] --main=<file> [--output=<file>|-] <regex1.wasm> ...
```

Merges the host main WASM with one or more regexp WASM modules into a single binary using `wasm-merge`. Each regexp module's memory is kept separate (multi-memory) and renumbered by wasm-merge.

This command is a thin wrapper around `wasm-merge`. You may invoke wasm-merge directly with:

```
wasm-merge --enable-multimemory --enable-simd --enable-bulk-memory --enable-bulk-memory-opt \
  <main.wasm> main <regexp.wasm> <module_name> ... \
  --rename-export-conflicts -o output.wasm
```

**Flags:**

| Flag | Default | Description |
|---|---|---|
| `--config` | `regexped.yaml` | YAML config file |
| `--main` | — | Host main WASM file **(required)** |
| `--output`, `-o` | config `output` | Output WASM file; `-` writes to stdout |

**Positional arguments:** one or more regexp WASM files (at least one required).

**Required config fields:**

| Field | Notes |
|---|---|
| `output` | Required unless `--output` is given |
| `wasm_merge` | Optional; path to wasm-merge binary; defaults to `$WASM_MERGE` env var, then `wasm-merge` in $PATH |
| `import_module` | Optional; module name passed to wasm-merge; defaults to basename of the regexp WASM |

---

## Typical workflows

### Rust deployment

```bash
# 1. Generate Rust stubs
regexped generate --config=regexped.yaml

# 2. Build your Rust project to WASM
cargo build --target wasm32-wasip1 --release

# 3. Compile regexp patterns to WASM (no --main needed)
regexped compile --config=regexped.yaml

# 4. Merge into a single binary
regexped merge --config=regexped.yaml --main=target/wasm32-wasip1/release/app.wasm pattern.wasm
```

### Go deployment

```bash
# 1. Generate Go stubs
regexped generate --config=regexped.yaml

# 2. Compile regexp patterns to WASM (no --main needed)
regexped compile --config=regexped.yaml

# 3. Build your Go project to WASM
GOOS=wasip1 GOARCH=wasm go build -o app.wasm .

# 4. Merge into a single binary
regexped merge --config=regexped.yaml --main=app.wasm regexp.wasm
```

### JS / Browser / Cloudflare Worker deployment

```bash
# 1. Compile regexp patterns to WASM (standalone, no merge needed)
regexped compile --config=regexped.yaml

# 2. Generate JS/TS stub
regexped generate --config=regexped.yaml

# 3. Load the compiled WASM directly in your JS/TS code:
#    await init(await fetch('./regexps.wasm').then(r => r.arrayBuffer()));
```

See [`examples/`](../examples/) for complete self-contained projects with Makefiles.
