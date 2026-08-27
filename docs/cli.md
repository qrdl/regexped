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
namespace:      "acme"     # optional; prefixes the symbols a stub declares that YOU did not name
                           #   (Span, SetMatch, the error type, the pattern-name helper, C's rx_*_t)
                           #   so two stubs can share one package. No-op for Rust, whose
                           #   `pub mod <import_module>` already isolates each stub.
max_dfa_states: 1024       # optional; max DFA/TDFA states before falling back to Backtracking (default 1024)
max_tdfa_regs:  32         # optional; max TDFA registers before falling back to Backtracking (default 32)
max_fallback_states: 1024  # optional; max suffix-DFA states for one fallback bucket in a SET (default 1024)

regexps:
  - pattern: 'https?://...' # RE2 regexp pattern
    name: "my_pattern"      # required when referenced by sets: patterns list

    # One or more func fields — only those set are compiled and stubbed.
    # The func name becomes both the WASM export name and the generated function name.
    # An entry with only 'pattern' is valid; no code is generated for it.
    match_func:        "url_match"         # anchored match
    find_func:         "url_find"          # non-anchored find
    groups_func:       "url_groups"        # match iterator; each item is that match's capture groups

    hints: [prefer-match, batch-find]   # optional; see "hints:" below

sets:
  - name: "my_set"             # unique set name
    # Five capabilities; declare the ones you need (at least one).
    match_any:  "which"        # anchored (whole input): one pattern id, or -1
    match_all:  "which_all"    # anchored: every matching pattern id
    scan_any:   "first_hit"    # non-anchored: one pattern id, or -1
    scan_all:   "all_kinds"    # non-anchored: every pattern matching somewhere
    find:       "locate"       # non-anchored: positions and extents
    overlapping: false         # optional; default false = per-pattern non-overlapping
    emit_name_map: true        # emit patternName(id) lookup helper in stubs
    patterns: all              # "all" or list of name: values from regexps:
    hints: [batch-find]        # optional; see "hints:" below
```

> **Three set keys were retired and are now load errors.**
>
> - **`match:` and `scan:`** — `match_any(...) >= 0` is exactly what `match`
>   returned and `scan_any(...) >= 0` what `scan` returned, and the redundancy
>   measured at 1-3% of module size. They were DROPPED rather than repurposed:
>   a surviving `match:` with `match_any` semantics would leave every existing
>   config compiling while its callers silently switched from reading 0/1 to
>   reading an id — and id 0 would read as "no match".
> - **`find_batch:`** — batching is no longer a second capability but a
>   property of `find`, requested with `hints: [batch-find]` on the set. At the
>   API level the two were never distinguishable: both iterate the same matches
>   in the same order, and the cursor and gate array are stub-owned and
>   invisible. The only caller-visible difference is how much work one host
>   crossing does, which is a parameter, not a name.

> **Config parsing is strict.** Any unknown key anywhere in the file is a
> line-numbered load error. That catches typos (`mach_func:`) and the retired
> set keys `find_any`, `find_all` and `batch_size`. It cannot catch the
> `match:` meaning change — see [sets.md](sets.md#the-eight-capabilities).

All paths in the config file are resolved relative to the config file's directory.
A leading `~/` in `output`, `wasm_file`, `stub_file` or `wasm_merge` is expanded to
the user's home directory (a bare `~` and the `~user` form are not expanded — only
a shell can resolve another user's home).

### Export-name rules

Every `match_func`, `find_func` and `groups_func` value, and every
set capability value (`match`, `match_any`, `match_all`, `scan`, `scan_any`, `scan_all`,
`find`), becomes both a WASM export name and a
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

#### Rules that depend on `stub_type`

The rules above are deliberately language-agnostic, so that changing `stub_type` never
breaks a working config. A second, narrower set of checks is the opposite: they apply
only to the generator the config actually targets, because enforcing them everywhere
would reject configs that are perfectly valid. They are skipped entirely for a
compile-only config (no `stub_type` and no `stub_file`), which generates no source.

| Check | Applies to | Rationale |
|---|---|---|
| `import_module` must be a valid identifier and not a keyword of that language | `rust`, `go` | Emitted as `pub mod <name>` / `package <name>`. A hyphenated `import_module: "my-mod"` stays legal for `js`/`ts`, which never emit it. |
| `import_module` must not contain `"`, `\`, or control characters | `c`, `as` | Emitted only inside a quoted import attribute; a `"` closes the string early. |
| Export names must not collide with a generator helper (`init`, `_w`, `_resize`, `_exp`, `_mem`, `_inBase`, `_outBase`, `_enc`, `_patternNames`, `patternName`, and `SetMatch` for TS) | `js`, `ts` | These are declared by the generated module itself; a collision is a duplicate declaration. |
| Export names must not start with `ffi_` | `rust`, `go` | `ffi_<export>` is the generated private FFI binding, so `ffi_x` collides with the shim for an export named `x`. |
| Export names must not collide after the snake_case → PascalCase transform | `rust` | `url_match` and `urlMatch` are distinct WASM exports but generate the same Rust iterator TYPE. Go dropped out of this rule: its names are now emitted verbatim, so nothing there transforms. |
| Capture group names must be usable as identifiers, unique, and not collide after sanitising | all, when `groups_func` is set | Group names become generated constants and a name→index lookup. `regexp/syntax` accepts `(?P<a>x)(?P<a>y)` and `(?P<host>x)(?P<Host>y)`; both would collapse to one generated symbol, so this check is ours. |

### Engine selection

Setting `groups_func` triggers capture-tracking compilation:
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
- **`batch-find`** — requests batching. On a `regexps:` entry it emits a
  `<func>_batch` WASM export for that pattern's `find_func` and/or
  `groups_func` (see below). On a `sets:` entry it emits one alongside the
  set's `find` and gives the generated `find` an optional `batchSize`
  parameter; it requires `find` on the same set, since there is otherwise
  nothing to batch. Emission is keyed on the HINT and never on `stub_type` —
  keying a module's export surface on the stub language would break the rule
  below that changing `stub_type` never breaks a working config.

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
`groups_func`. One capability means one batch export and one name; the rule
about two capture keys sharing an export went with `named_groups_func`.

**⚠ This hint is effective for the JS and TS generators only.** The generated
JS/TS `find_func`/`groups_func` consumer feature-detects
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

Errors are always printed regardless of `--debug`; the flag only controls the
diagnostic chatter below warning level.

---

## Exit codes

| Code | Meaning | Examples |
|---|---|---|
| `0` | Success. Also returned by `-h` on any subcommand. | |
| `1` | Usage error — the command line is wrong. | No subcommand, unknown subcommand, unrecognised flag, missing `--main`/`--output`, `--output=-` and `--diag-json=-` both writing to stdout |
| `2` | Config or build error — the command line was fine, the work was not. | Malformed YAML, invalid export name, duplicate capture-group name, missing `import_module`, compile/generate/merge failure |
| `3` | I/O error — a file could not be read or written. | Config file does not exist, config file not readable, output path not writable |

Codes `2` and `3` are distinguished by inspecting the error: anything carrying a
filesystem failure reports `3`, everything else reports `2`. So a config file that is
missing is `3`, while a config file that is present but invalid is `2`.

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

Wraps every entry in one `pub mod <import_module> { … }` block.

| Config field | Generated function | Return type |
|---|---|---|
| `match_func` | `<func>(input)` | `Result<Option<usize>>` |
| `find_func` | `<func>(input, offset)` | `<Func>Iter` — yields `Result<(usize, usize)>` |
| `groups_func` | `<func>(input, offset)` | `<Func>Iter` — yields `Result<Vec<Option<Span>>>` |

Every export reports a Backtracking overflow as `Err(Error::BacktrackOverflow)`;
the iterators are fused. See [rust-api.md](rust-api.md).

#### Go stubs (`GOOS=wasip1`)

Generates a `//go:build wasip1` file using `//go:wasmimport` declarations.
Requires `import_module` in config (used as the Go package name) and Go 1.23+
(iterators use `iter.Seq2` / `iter.Seq`).

| Config field | Generated function | Return type |
|---|---|---|
| `match_func` | `<func>(input []byte)` | `(end uint, ok bool, err error)` |
| `find_func` | `<func>(input []byte, offset uint)` | `*<func>Iter` — `Matches() iter.Seq2[uint, uint]`, `Err() error` |
| `groups_func` | `<func>(input []byte, offset uint)` | `*<func>Iter` — `Matches() iter.Seq[[]Span]`, `Err() error` |

**Function names are your config names, verbatim** — `url_match` stays
`url_match`. The PascalCase transform is gone. In a library package that leaves
the symbol unexported; the generator warns once rather than renaming it. See
[go-api.md](go-api.md).

#### JS and TS stubs

A single ES module. `init(wasm)` must be awaited before any matcher is used.

| Config field | Generated export | Yields |
|---|---|---|
| `match_func` | `function <func>(input)` | `number \| null` |
| `find_func` | `function* <func>(input, offset)` | `[start, end]` per match |
| `groups_func` | `function* <func>(input, offset)` | `Array<[start, end] \| null>` per match |

Overflow **throws**, which is JS's own error channel. TS is the same surface
with type annotations. See [js-api.md](js-api.md) and [ts-api.md](ts-api.md).

#### C stubs

A `#pragma once` header plus a `.c`. No libc or sysroot required.

| Config field | Generated functions | Notes |
|---|---|---|
| `match_func` | `ptrdiff_t <func>(input, len)` | end position, `-1`, or `RX_ERR_BT_OVERFLOW` |
| `find_func` | `<func>_init` + `<func>_next(iter, &match)` | caller-owned iterator; `1` / `0` / `RX_ERR_BT_OVERFLOW` |
| `groups_func` | `<func>_init` + `<func>_next(iter, groups)` | fills the caller's `rx_group_t[]` |

C returns sentinels — it has no unwinding, and its return types were already
error codes. See [c-api.md](c-api.md).

#### AS stubs (AssemblyScript)

An AssemblyScript `.ts` using `@external` declarations. Requires
`import_module`, and `stub_type: "as"` — a `.ts` extension alone infers
TypeScript. Input is `ArrayBuffer`.

| Config field | Generated function | Returns |
|---|---|---|
| `match_func` | `<func>(input): i32` | end position, `-1`, or `RX_ERR_BT_OVERFLOW` |
| `find_func` | `<func>(input, offset): <func>_iter` | `next(): i64` — packed pair, `-1`, or `RX_ERR_BT_OVERFLOW` |
| `groups_func` | `<func>(input, offset): <func>_iter` | `next(): u32` — slot pointer, `0`, or `RX_ITER_ERROR` |

AssemblyScript returns sentinels, not exceptions: `asc` cannot `catch`, and a
`throw` there compiles to an uncatchable `abort`. See [as-api.md](as-api.md).

#### Named capture groups

There is no `named_groups_func` — it was retired, because it was never a
separate capability: both stubs called the same WASM export. When a pattern has
at least one named group, `groups_func` additionally emits a constant per named
group plus `<func>_index` and `<func>_names` (an index object in JS/TS). This
also gives C and AssemblyScript named access, which they never had.

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

When the config contains a `sets:` block, `compile` also emits multi-pattern set-match functions. Each set entry produces one exported WASM function per declared capability, plus a batch entry when it asks for one.

```yaml
regexps:
  - name: aws_key      # name is required for sets: pattern references
    pattern: 'AKIA[0-9A-Z]{16}'
  - name: github_pat
    pattern: 'ghp_[0-9a-zA-Z]{36}'

sets:
  - name: secret_scanner
    find: scan_secrets       # non-anchored: matches at the next matching position
    scan_any: which_secret   # non-anchored: one pattern id, or -1 (optional)
    match_any: validate      # anchored (whole input): one pattern id (optional)
    hints: [batch-find]      # optional: work several positions ahead per call
    emit_name_map: true      # emit pattern_name(id) helper in stubs
    patterns:
      - aws_key              # list of regexps.name values
      - github_pat
      # or: patterns: "all" to include every entry in regexps:
```

| `sets:` field | Required | Description |
|---|---|---|
| `name` | Yes | Unique set name |
| `match_any` | At least one | Anchored (whole input): one matching pattern id, or -1 |
| `match_all` | At least one | Anchored: every matching pattern id |
| `scan_any` | At least one | Non-anchored, takes `offset`: one pattern id, or -1. Reports NO position |
| `scan_all` | At least one | Non-anchored: every pattern matching somewhere |
| `find` | At least one | Non-anchored: every match at the next matching position — the only capability reporting positions and extents |
| `overlapping` | No | `false` (default) = per-pattern non-overlapping; `true` = every start position. Affects `find` only, and is silently ignored on a set without it |
| `patterns` | Yes | Either `"all"` or a list of `name:` values from `regexps:` |
| `emit_name_map` | No | Emit `pattern_name(id)` lookup in generated stubs |
| `hints` | No | `[prefer-match]` or `[prefer-no-match]` (per-set LikelyMode default), and/or `[batch-find]`, which requires `find` — see [`hints:`](#hints--likelymode-and-batch-find-compile-hints) above |

`match:`, `scan:` and `find_batch:` are **retired keys** and are load errors;
see the note under the schema above.

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
| `--output`, `-o` | config `output` | Output WASM file (must be a path; `-` is not accepted) |

**Positional arguments:** one or more regexp WASM files (at least one required).

Unlike `generate` and `compile`, `merge` does not accept `-` for stdout: the
value is handed straight to `wasm-merge`, which would create a file literally
named `-`.

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
