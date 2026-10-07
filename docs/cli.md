# Regexped CLI Reference

## Configuration File

Regexped is driven by a YAML config file (default: `regexped.yaml` in the current directory).

```yaml
wasm_format: "module"      # optional; "module" (default) or "component" — see "Output kinds" below
wasm_merge_path: "tools"   # optional; where wasm-merge is (merge, wasm_format: module). A FILE is the
                           #   tool itself, so it may be named anything; a DIRECTORY gets `wasm-merge`
                           #   appended. Relative to this config file; `~` and `~/dir` expand to $HOME.
                           #   Omitted → `wasm-merge` in $PATH. No environment variable is read.
wasm_tools_path: "tools"   # optional; the same rule for wasm-tools (wasm_format: component — compile,
                           #   and merge, which reads each plug's exports with it)
wac_path: "tools"          # optional; the same rule for wac (merge, wasm_format: component)
output:   "merged.wasm"    # output path for the merge command; overridable with --output. The merge
                           #   target in both formats; under wasm_format: component it does not select
                           #   the memory mode (a component owns its own memory)
wasm_file: "regexps.wasm"  # output path for the compile command; overridable with --output
import_module: "mymod"     # the WASM import-module name — a WIRE string, and the default for the
                           #   three source-identifier keys below
rust_module: "mymod"       # optional; the Rust `pub mod` name.   Defaults to import_module
go_package:  "mymod"       # optional; the Go `package` name.     Defaults to import_module
wit_package: "my-mod"      # optional; the WIT package name.      Defaults to kebab(import_module)
wit_world:   "my-mod"      # optional; the WIT world name.        Defaults to wit_package
wit_version: "1.2.0"       # optional; component only. UNSET MEANS NO VERSION — see "Versioning" below
stub_file: "src/stubs.rs"  # stub output file; extension determines type: .rs, .js, .ts, .go, .h, .wit
stub_type: "rust"          # optional; overrides extension-based type inference: rust, js, ts, go, c, as, wit
namespace:      "acme"     # optional; prefixes the fixed symbols a stub declares — Span, SetMatch,
                           #   the error type, the pattern-name helper, C's rx_match_t, rx_group_t and
                           #   rx_set_match_t — so two stubs can share one package. It does NOT prefix
                           #   names you choose: func and capability names, or what a set's NAME
                           #   derives (<SET>_PATTERN_COUNT, <SET>_ID_SPACE, rx_<set>_scanner_t,
                           #   <Set>PatternCount). Two stubs in one package or C translation unit need
                           #   distinct set names, and choosing them is yours. No-op for Rust, whose
                           #   `pub mod <rust_module>` already isolates each stub.
max_dfa_states: 1024       # optional; max DFA/TDFA states before falling back to Backtracking
                           #   (default 1024; 16384 for a pattern in Unicode mode, see `unicode:`)
max_tdfa_regs:  32         # optional; max TDFA registers before falling back to Backtracking (default 32)
                           #   `compile --verbose` prints, per pattern, the engine chosen, why, and
                           #   the DFA/TDFA state and TDFA register counts against these limits
max_fallback_states: 1024  # optional; max suffix-DFA states for one fallback bucket in a SET (default 1024; 16384 for a Unicode-mode set)
                           #   A member over it moves to the Backtracking engine, with a warning;
                           #   `compile --verbose` prints each bucket's engine
max_union_states: 4096     # optional; max states while building a SET's union automata (default 4096)
                           #   — see "max_union_states:" below
max_memory: 100MB          # optional; the most memory the module may ever use (default: no cap).
                           #   KB/MB/GB = powers of 1,000, KiB/MiB/GiB = powers of 1,024, any case,
                           #   fractions allowed; a bare number is bytes. See "max_memory:" below

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
    byte_mode: false           # optional; see "byte_mode:" below
    unicode: false             # optional; see "unicode:" below

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
    unicode: false             # optional; the set's mode — see "unicode:" below
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
> set keys `match`, `scan`, `find_batch`, `find_any`, `find_all` and
> `batch_size` — see [sets.md](sets.md#the-five-capabilities).

> **Three tool keys were retired and are now load errors:** `wasm_merge:`,
> `wasm_tools:` and `wac:`. Use `wasm_merge_path:`, `wasm_tools_path:` and
> `wac_path:`. The `$WASM_MERGE`, `$WASM_TOOLS` and `$WAC` environment variables
> are no longer read either: a tool is found through its key or in `$PATH`, and
> nothing else.

All paths in the config file are resolved relative to the config file's directory.
A leading `~/` in `output`, `wasm_file` or `stub_file` is expanded to the user's
home directory (a bare `~` and the `~user` form are not expanded — only a shell
can resolve another user's home).

The three tool keys follow one rule of their own. Omitted, the tool is looked up
by its fixed name in `$PATH`. Given, the value is a path: relative to the config
file's directory, with `~` alone and `~/dir` expanded to the home directory
(`~user` is taken literally, as a relative path, which is what Bash does for an
unknown user). What it points at decides how it is used: a file, or a symlink to
one, IS the tool, so a tool installed under another name (`wasm-merge-118`)
works; a directory, or a symlink to one, gets the tool name appended. A tool that
cannot be found is reported with the key, the value as written, and the exact
path tried.

### Export-name rules

Every `match_func`, `find_func` and `groups_func` value, and every
set capability value (`match_any`, `match_all`, `scan_any`, `scan_all`,
`find`), becomes both a WASM export name and a
function name in the generated stub. Because they are written verbatim into generated
source, they are validated when the config is loaded, before any compile or generate work
runs. A violation is a hard error: nothing is written and the exit status is non-zero.

- **Shape** — must match `^[A-Za-z_][A-Za-z0-9_]*$`. ASCII only, no leading digit. This is
  stricter than Rust, Go, JS and TS individually allow (all four accept some non-ASCII
  identifiers), so that one config is portable across every `stub_type`.
- **Reserved words** — the name must not be a reserved word in the language `stub_type`
  generates: Rust, Go, C, JavaScript, TypeScript or AssemblyScript. A `wasm_format:
  component` config, or `stub_type: wit`, is also checked against WIT's keywords, and for
  a Rust component stub the snake_case name wit-bindgen binds must not be a Rust keyword
  either. A compile-only config — no `stub_type` and no `stub_file` — generates no source,
  so only the shape rule applies to it. Notably `match` is refused for a Rust stub; `find`
  and `groups` are fine everywhere.
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
| The **effective Rust module name** must be a valid identifier and not a Rust keyword | `rust` | Emitted as `pub mod <name>`. The name is `rust_module`, falling back to `import_module` — so a config setting neither gets exactly the check it always got, and setting `rust_module` is the escape hatch for a wire name like `match` that is a keyword, or `url_ipv6` that you would rather not see as a module name. |
| The **effective Go package name** must be a valid identifier and not a Go keyword | `go` | Emitted as `package <name>`. The name is `go_package`, falling back to `import_module`, with the same escape hatch. |
| `import_module` must not contain `"`, `\`, or control characters | `c`, `as` | Emitted only inside a quoted import attribute; a `"` closes the string early. This is the ONLY rule that applies to `import_module` itself: it is a wire string, so a keyword or a hyphen in it is fine. |
| `wit_package` / `wit_world` must be WIT identifiers — `[a-z][a-z0-9]*(-[a-z][a-z0-9]*)*` | every `wasm_format: component` config, and `stub_type: wit` | Emitted as the WIT package and world. Unset, they derive from `import_module` by kebab-casing; a name that cannot be represented (`_x`, `x__y`, `9x`, `my.mod`) is an error telling you to set `wit_package`, never a silent rename. |
| Export names must not collide with a generator helper (`init`, `_exp`, `_mem`, `_staticTop`, `_bump`, `_live`, `_enc`, `_align`, `_grow`, `_inCap`, `_write`, `_stage`, `_open`, `_close`, `_att`, `_patternNames`, `patternName`, plus `SetMatch` and `SetAnchor` for TS) | `js`, `ts` | These are declared by the generated module itself; a collision is a duplicate declaration. |
| Export names must not collide with a generator helper (`Span`, `ErrBacktrackOverflow`, `ErrMalformedCache`, `ErrOutOfOrder`, `SetMatch`, `PatternName`, `init`) | `go` | Same reason. `init` is reserved by the LANGUAGE: `func init` takes no arguments and returns nothing, so a stub function named `init` does not compile. |
| Export names must not collide with a generator helper (`rx_match_t`, `rx_group_t`, `rx_set_match_t`, `pattern_name`, `RX_ERR_BT_OVERFLOW`, `RX_ERR_MALFORMED_CACHE`, `RX_ERR_OUT_OF_ORDER`, `RX_ERR_NULL_ARG`, `RX_ERR_RANGE`, `REGEXPED_TYPES_DEFINED`, and the component stub's `cabi_realloc`, `regexped_cabi_mark`, `regexped_cabi_release`, `regexped_cabi_foreign_allocator`, `rx_cabi_heap`, `rx_cabi_used`, `rx_cabi_copy`, `rx_cabi_u32`, `rx_pattern_names`, `RX_CABI_EXPECT_OURS`) | `c` | Same reason. The component stub's allocator helpers are deliberately NOT namespaced: every regexped stub in one guest shares them by name. |
| Export names must not collide with a generator helper (`SetMatch`, `patternName`, `RX_ERR_BT_OVERFLOW`, `RX_ERR_MALFORMED_CACHE`, `RX_ERR_OUT_OF_ORDER`, `RX_ITER_ERROR`, `Span`) | `as` | Same reason. |
| Export names must not start with `ffi_` | `rust`, `go`, `c` | `ffi_<export>` is the generated private FFI binding, so `ffi_x` collides with the shim for an export named `x`. |
| Export names must not collide after the snake_case → PascalCase transform | `rust` | `url_match` and `urlMatch` are distinct WASM exports but generate the same Rust iterator TYPE. Go dropped out of this rule: its names are now emitted verbatim, so nothing there transforms. |
| An export must not be named `<X>Iter` for another find/groups export `X` | `go`, `as` | Every find or groups export declares an iterator type of that name. This is Go's real collision surface, where the PascalCase rule above is not. |
| An export must not collide with a symbol DERIVED from another export (`<func>_index`, `<func>_names`, `<func>_count`, `<func>_indices`, `<func>_iter`, in the base name's own casing style) | all | `groups_func: parse` emits `parse_index` and friends; a second export literally named `parse_index` duplicates the symbol. |
| `namespace:` must be a valid identifier and not a reserved word | all | It is interpolated verbatim into generated identifiers in Go/JS/TS/AS/C. |
| An export must not be the blank identifier `_` | all | Shape-legal, but `pub fn _` is invalid Rust and `func _()` is invalid Go. |
| Capture group names must be usable as identifiers, unique, and not collide after sanitising | all, when `groups_func` is set | Group names become generated constants and a name→index lookup. `regexp/syntax` accepts `(?P<a>x)(?P<a>y)` and `(?P<host>x)(?P<Host>y)`; both would collapse to one generated symbol, so this check is ours. |
| Capture group names must not be `index`, `names`, `count` or `indices` | all, when `groups_func` is set | Those are the suffixes the generators derive from the `groups_func` name, so a group of that name produces the same symbol twice in one file. |
| A `groups_func` pattern must have a capture group that can take part in a match | all | `a*`, or `(?:(a){0})b`, whose only group simplification removes, has no groups to report: it would compile to no groups export while every stub calls one. `compile` and `generate` refuse it too. Use `find_func` for the match's span. |

### Engine selection

Setting `groups_func` triggers capture-tracking compilation:
- **TDFA engine** — used when the pattern has no non-greedy quantifiers, no line anchors, no word boundaries, and no ambiguous alternations (Laurikari's tagged DFA, O(n))
- **Backtracking engine** — used automatically as a fallback for patterns that are not TDFA-eligible (e.g. `(a|ab)`, `(a*)(a*)`)

Setting only `match_func` and/or `find_func` uses the **DFA engine**. Capture groups are stripped from the pattern before compilation.

See [engines.md](engines.md) for full details on engine selection and capabilities.

### `max_memory:` — a cap on the module's memory

Every pattern and set in a config compiles into ONE module with one memory,
and WebAssembly memory never shrinks. `max_memory` caps it: the value is
declared as the memory's **maximum**, so the WebAssembly engine refuses every
grow past it, whoever asks. Unset — the default — there is no cap.

**When to set it.** The Backtracking engine's frame stacks and fallback memo
grow with the input when a search backtracks hard, so a module that carries
Backtracking code — a pattern on that engine, a `find` whose switch hands over
to it, or a set member on it — can be made to grow its memory by an
adversarial input until the host runs out. `regexped compile` therefore warns
when such a module has no cap:

```
WARN Backtracking engine selected and max_memory is not set: memory is not limited, possible out-of-memory on adversarial input
```

`compile --verbose` names the patterns on Backtracking. With a cap, a search
that would need more answers "unknown" (`-2`) instead, and every other search
is unaffected; `examples/wasmtime/go/sql-injection` sets one. See
[complexity.md](complexity.md) for every per-input-byte memory cost.

```yaml
max_memory: 100MB    # 100,000,000 bytes → 1,525 pages of 64 KiB
```

**Spelling.** A number, fractions allowed, optionally followed by a unit, with
or without a space: `100MB`, `100 MB`, `1.5GB`, `64KiB`, `100mib`. `KB`, `MB`
and `GB` are powers of 1,000; `KiB`, `MiB` and `GiB` powers of 1,024; letter
case does not matter. A bare number is bytes. The value is rounded **down** to
whole 64 KiB pages, the unit a memory is declared in. Anything else — a sign,
an exponent, another unit — is a line-numbered load error.

**What it counts:** all of the module's own memory — its tables, the buffers a
JS/TS stub copies each input into and reads answers from, and a search's
working memory (the Backtracking engine's frame stacks and memo, and the
default search state a standalone module keeps for a raw caller). In a merged
Rust/Go/C build the input lives in the host's memory, so there the cap covers
the tables and the search's working memory only.

**What happens at the cap:**

- A search that needs more memory than the cap leaves answers "gave up" (`-2`),
  which every stub reports as an error rather than as "no match" — never a
  wrong answer.
- In JS/TS, an input that does not fit under the cap by itself makes the call
  **throw** a `RangeError` ("Maximum memory size exceeded") before any search
  runs — for every pattern, whatever its engine. `init()` grows memory by two
  pages, so a cap only just above the tables compiles but makes `init()` throw.
- In a component, the allocator traps when an input does not fit. The
  optional working memory — a set's overlapping answer cache, a search's
  notes and its kept Backtracking memo — is never a trap: when it does not
  fit under the cap the component goes without it, as a module's stubs do,
  and answers the same. So does the default state a standalone module keeps
  for a caller that hands it none (see [wasm.md](wasm.md), "Handing the block
  over").
- A module whose tables are already over the cap is a **compile error** naming
  the cap and the size. Backtracking reserves nothing there: its frame stacks
  are claimed when a search runs. A value below 64 KiB rounds
  down to 0 pages and always gets it.
- A 32-bit WebAssembly memory holds at most 4 GiB. A larger value is treated as
  4 GiB, with a compile warning saying so.

### `max_union_states:` — the budget of a set's union automata

A set whose members have no literal to search for is scanned by ONE automaton
built over all of them: `scan_any` and `scan_all` read the input once, whatever
the member count. `match_any` and `match_all` use an anchored automaton of the
same kind. `max_union_states` (default 4,096) caps their construction. A set
past the cap still answers correctly, by a slower route: members that are not
provably linear are split out to searches of their own, and the rest are walked
position by position. `compile --diag-json` shows which route a set took
(`union_scan.used`, and `refused: "construction"` when the cap was the reason).

The cap matters most in Unicode mode, where a letter class such as `\pL` costs
hundreds of states, so a few literal-less members can pass 4,096. Measured on
an 8-member Unicode-mode set, scanning 64 KB of mixed-script text that no
member matches:

```yaml
max_union_states: 16384
regexps:
  - { name: m0, pattern: '\pL+\p{Greek}' }
  - { name: m1, pattern: '\p{Greek}+\p{Cyrillic}' }
  - { name: m2, pattern: '\p{Cyrillic}+\p{Han}' }
  - { name: m3, pattern: '\p{Han}+\pN' }
  - { name: m4, pattern: '\pN+\p{Lu}' }
  - { name: m5, pattern: '\p{Lu}+\p{Ll}' }
  - { name: m6, pattern: '\p{Ll}+[^\x00-\x7f]' }
  - { name: m7, pattern: '[^\x00-\x7f]+\pL' }
sets:
  - name: s
    scan_any: s_any
    scan_all: s_all
    patterns: all
```

| `max_union_states` | union automaton | `scan_all` fuel per byte | module | compile time |
|---|---|---|---|---|
| 4096 (default) | refused: needs more states | 102 (members split out) | 1.39 MB | 55 s |
| 16384 | 2,179 states | 23 | 0.94 MB | 173 s |

A larger cap costs compile time and compiler memory, never correctness; a
32-member set of the same kind did not fit in 16,384, and at 65,536 its
construction ran out of 4 GB of compiler memory. In byte mode the cap is
reached by shapes that must remember many positions at once, such as
`a.{13}b`.

### `byte_mode:` — matching raw bytes above 127

A pattern is matched byte by byte unless it asks for Unicode mode: `.` consumes
one byte, classes are byte classes, and `\b` is ASCII. A pattern naming a rune
above U+007F asks for Unicode mode (see `unicode:` below), where `é` means the
character, two bytes of UTF-8.

Setting `byte_mode: true` on a `regexps:` entry declares the pattern
byte-oriented instead: runes `0x80`-`0xFF` mean **exactly that byte**.

```yaml
regexps:
  - name: utf8_lead
    pattern: '[\xc0-\xdf]'        # a UTF-8 two-byte lead — needs byte_mode
    byte_mode: true
    find_func: find_lead
```

Runes above `U+00FF` are rejected under `byte_mode` — no byte holds one:

```
pattern contains the rune U+03B1, above U+00FF, which byte mode cannot match;
without byte mode the pattern compiles in Unicode mode
```

The flag is per pattern because it is a statement about that pattern's text,
and it applies to set members as well as to `_func` patterns. Rust's regex
crate spells the same distinction `(?-u)` / `regex::bytes`; an inline flag was
not chosen here because Go's parser rejects `(?-u)` outright.

**What does not ask for Unicode mode**, so a pattern with nothing else stays in
byte mode:

- **`.` and negated classes.** `[^,]` names every rune there is, and consumes
  one byte. This is documented byte semantics, not an oversight.
- **Case-fold artifacts of ASCII.** Go's parser expands `(?i)` over a class
  eagerly, so `(?i:[a-z])` arrives carrying U+017F (long s) and U+212A (Kelvin
  sign) — runes you did not write, manufactured from the `s` and `k` you did.
  `(?i)` therefore keeps working over letter classes, `\w` and ASCII literals,
  and over NEGATED classes too: `(?i)[^a-z]` and `(?i)\W` arrive with holes at
  exactly those runes, and match every byte that is not a letter (or word
  character), `0x80`-`0xFF` included. Under `byte_mode` `(?i)` over Latin-1
  adds U+212B (from `å`) the same way. A rune you DID write asks for Unicode
  mode, negated or not, and under `(?i)` too: `[^ſ]`, `[sſ]`, `[sSſ]`,
  `[^sSſ]` and `(?i)[sſ]` all write `ſ`, as a character, a `\x{17F}` escape or
  the octal `\577`; under `byte_mode` they are refused, since no byte is `ſ`.
  The consequence is that in byte mode `(?i)k` does not match a Kelvin sign
  and `(?i:[a-z]+)` does not match a long s: folding stays within the bytes.
  `unicode: true` folds across Unicode, as Go does.

### `unicode:` — codepoint mode

What Unicode mode
changes — `.` and classes reading whole UTF-8 characters, `(?i)` across
Unicode, no match starting inside a character, invalid bytes matching nothing
— is in [engines.md](engines.md#unicode-mode).

On a `regexps:` entry:

- **No key** — the pattern picks its own mode: Unicode when it names a
  character above U+007F or uses a `\p{..}` / `\P{..}` class, byte mode
  otherwise. `.` and negated classes never pick Unicode by themselves.
- **`unicode: true`** — Unicode mode even for an ASCII-only pattern, which is
  how to make `.` match a whole character.
- **`unicode: false`** — exactly `byte_mode: true`.
- `unicode: true` with `byte_mode: true`, and `unicode: false` with
  `byte_mode: false`, on the same entry are load errors.

```yaml
regexps:
  - name: word
    pattern: '\pL+'          # Unicode mode: names a Unicode class
    find_func: find_word
  - name: any3
    pattern: 'a.c'
    unicode: true            # Unicode mode on request: `.` is one character
    find_func: find_any3
  - name: raw
    pattern: '[\xc0-\xdf]'
    unicode: false           # the same as byte_mode: true — raw bytes
    find_func: find_raw
```

On a `sets:` entry the key sets the set's mode, and a set runs in one mode:

- A member that sets `byte_mode: true` or `unicode: false`, together with a
  member that asks for Unicode (by its key or by its pattern), is a compile
  error; so is a set-level `unicode: true` with such a byte member, or a
  set-level `unicode: false` with a member asking for Unicode.
- Otherwise one member asking for Unicode puts the whole set in Unicode mode,
  and members that say nothing follow it; failing that, the set-level key
  decides, and with neither the set runs in byte mode.
- A pattern's own `match_func` / `find_func` / `groups_func` follow the
  pattern's rule above, whichever mode a set it belongs to runs in.

`compile --verbose` and `--diag-json` report the mode each pattern and set
was compiled in.

**`max_dfa_states` is 16,384 by default for a pattern in Unicode mode**
(1,024 in byte mode). A Unicode class is decoded byte by byte, so it costs
DFA states per position — about 290 for `\pL` — and a pattern over the limit
falls back to Backtracking, whose program grows with the class too: `\pL{5}x`
needs 1,452 states and measured 39 fuel per byte as a DFA against about
26,000 on Backtracking. A DFA table over 256 states takes 512 bytes per state,
so the default allows about 8 MB per automaton. When a pattern needs more and
its Backtracking program is over that engine's fixed limit of 20,000
instructions, the compile error says which, and `compile --verbose` prints the
state count and, for a Unicode-mode pattern, the working memory a search keeps
per input byte (`memory:` lines). `tools/pattest` takes `-max-dfa-states N`
to measure what a different limit does to your pattern.

**`max_fallback_states` is 16,384 by default for a set in Unicode mode** too
(1,024 in byte mode), for the same reason: a member over it runs on
Backtracking. On a 32-member set over 64 KB of mixed-script text, the one
member past 1,024 (`\pL{4}\pN`, 1,250 states) on Backtracking took `scan_all`
to 152,500 fuel per byte; as a DFA, 2,661, in a smaller module (3.7 MB
against 5.5 MB).

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

`prefer-match`/`prefer-no-match` resolve **per entry, with no fallback chain
between the two levels**. A `regexps:` entry's hint governs only that
pattern's own exported bodies (`match_func`/`find_func`/`groups_func`); a
`sets:` entry's hint governs only that set's own frontend and bucket suffix
bodies. A set's hint is not inherited by a member's own exported bodies, and a
member's hint does not reach the set's bucket code — a bucket holds one merged
suffix DFA for several patterns, so there is no per-pattern choice for it to
honour. An entry with no `hints:` is neutral regardless of what encloses it.

`batch-find` has no fallback to resolve either: it is read on the entry (or
set) that carries it, and each one decides for itself. On a `regexps:` entry
it requires `find_func` or `groups_func`, and on a `sets:` entry it requires
`find` — there is otherwise nothing to batch, and accepting the hint anyway
would leave the caller believing they had asked for something.

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
| Unicode: characters above U+007F, `\p{..}` classes, `(?i)` across Unicode | Yes — [Unicode mode](#unicode--codepoint-mode) |

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
| `2` | Config or build error — the command line was fine, the work was not. | Malformed YAML, invalid export name, duplicate capture-group name, missing `import_module`, an unknown `wasm_format`, a set with `hints: [batch-find]` under `wasm_format: component`, compile/generate/merge failure |
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

Generates a stub file (Rust, JS, TypeScript, Go, C, AssemblyScript, or WIT) from the config. The stub type is determined by:

1. `stub_type` field in YAML (`rust`, `js`, `ts`, `go`, `c`, `as`, `wit`)
2. Extension of `stub_file` in YAML (`.rs` → rust, `.js` → js, `.ts` → ts, `.go` → go, `.h` → c, `.wit` → wit)
3. Error if neither resolves to a known type

**Which types are available depends on `wasm_format`**, which is why the output kind is a config key rather than a flag — `generate` has to make the same choice `compile` did:

| `wasm_format` | Accepted | Refused |
|---|---|---|
| `module` (default) | `rust`, `js`, `ts`, `go`, `c`, `as` | `wit` — "stub_type \"wit\" requires wasm_format: component" |
| `component` | `wit`, `rust`, `c` | `go`, `as`, `js`, `ts` — "… is not supported for wasm_format: component", with no "yet": none is a component target. Stock Go has no wasip2 target, so a Go component stub would have to be TinyGo; AssemblyScript has no planned route; and no JavaScript runtime loads a component, so a JS/TS consumer needs `jco transpile`, which lands on the core module the `module` format already produces. |

Under `component`, `stub_type: rust` and `stub_type: c` generate stubs whose public API is identical to the module-format ones; `wit` emits the interface alone, for a consumer that binds against it directly (a host using `wasmtime::component::bindgen!`, for instance).

The C stub additionally writes a `wit/` directory beside itself — `wasm-tools component embed` resolves `deps/` only when given that directory.

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
| `import_module` | Required for Rust, Go, C, and AS stubs; validated upfront. Also required (or `wit_package`) under `wasm_format: component`, where it names the WIT package, the world, and every export |

#### Rust stubs

Wraps every entry in one `pub mod <rust_module> { … }` block (`rust_module` defaults to `import_module`).

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

Compiles each regexp pattern to a single WASM module, or to a Component Model component.

A compile can take minutes — a Unicode-mode set's union automaton, a large
TDFA — and that is the price of a faster module. Any automaton construction
that runs past 5 seconds prints a line on stderr, and another every 5 seconds
after it, so a long compile is visibly working:

```
regexped: compiling set "s": DFA construction, 12400 of 16384 states so far (38 s)
```

A compile under 5 seconds prints nothing, and the module is the same either way.

### Output kinds

`wasm_format` selects the kind. It is a **config key, not a CLI flag** — there is deliberately no `--wasm-format` and no `--component` — because `generate` must make the same choice, and a flag lets the two commands diverge.

**`wasm_format: module`** (the default) is today's core WASM module, with two memory modes selected automatically:

- **Standalone** (no `output` field in config) — the module owns its memory, DFA/TDFA tables start at address 0. Load directly in JS/TS without merging.
- **Embedded** (`output` field present) — the module imports memory from a `"main"` host module. Use `regexped merge` to combine with a Rust/Go/C host binary.

**`wasm_format: component`** produces a Component Model component plus a sibling `.wit` (the same path as `wasm_file` with the extension replaced), by wrapping the core module through `wasm-tools`. Standalone memory is **forced** — a component owns and exports its own memory — so the standalone-vs-embedded choice above is not made here, and `output:` does not drive it. `output:` still means what it means for a module: the `regexped merge` target. Requires `wasm-tools` (`wasm_tools_path:`, else `$PATH`) to build and to merge, and `wac` (`wac_path:`, else `$PATH`) to merge.

The `.wit` is written BEFORE the component, so a `.wit` that cannot be written leaves no fresh `.wasm` behind. `--output -` streams the component to stdout and writes no `.wit`, since there is no path beside it; a line on stderr says so. Get the interface text with `regexped generate` and `stub_type: wit`.

Refused at load under `component`, rather than half-emitted. `batch-find` is a
design decision, not a missing feature: batching only ever saves host↔WASM
crossings, only the JS and TS stubs generate it, and neither is a component
target — so there is no host under `component` it could help.

| Config | Error |
|---|---|
| a set with `hints: [batch-find]` | "…is not supported for wasm_format: component — the component interface exposes one position per call through the find resource" |
| a `regexps:` entry with `hints: [batch-find]` | "…is not supported for wasm_format: component — the batch groups export it adds has no WIT form" |
| no `import_module` and no `wit_package` | "…is required for wasm_format: component: it names the WIT package, the world, and every export" |

`sets:` IS supported. Their raw ABI does not cross the boundary: `match_all` and
`scan_all` return a list of pattern ids instead of a bitmask or a caller-owned
bitmap, and `find` becomes a `resource` that owns the drive — the gate array the
module ABI makes the caller own has nowhere to live in a component consumer. The
generated Rust and C stubs present the same API either way; see
[component.md](component.md#sets) and [sets.md](sets.md).

See [component.md](component.md) for the generated interface and how to consume it.

### Versioning the component interface

`wit_version` is optional and **unset means no version at all**: the package is `package regexped:<name>;` and exports are named `regexped:<name>/matcher#<func>`. Set it and `@x.y.z` is appended to the package — and therefore to every export name.

That makes adding, removing or changing it a **breaking change** for anyone who built against the component: every export is renamed, and their build fails with a missing import. It is opt-in and loud, by design. Under `wasm_format: module` the key is inert and warns.

**Flags:**

| Flag | Default | Description |
|---|---|---|
| `--config` | `regexped.yaml` | YAML config file |
| `--output`, `-o` | config `wasm_file` | Output WASM file; `-` writes to stdout |
| `--diag-json` | (none) | Write set-composition diagnostics as JSON to this path; `-` for stdout |
| `--verbose` | off | Report what the compiler decided per pattern and per set, to stderr |

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

### `merge` — Link your binary with regexped's

```
regexped [--debug] merge [--config=<file>] --main=<file> [--output=<file>] <regex1.wasm> ...
```

Links the host main WASM with one or more regexp WASM artifacts into a single binary. **The command does not depend on the output kind** — it dispatches on `wasm_format` and runs the right tool:

| `wasm_format` | Tool | What it does |
|---|---|---|
| `module` (default) | `wasm-merge` | merges the core modules into one. Each regexp module keeps its own memory (multi-memory), renumbered by wasm-merge |
| `component` | `wac plug` | composes the components. `--main` is the **socket** (the component with the unsatisfied import); each positional is a **plug** |

A component config that ran `merge` before this dispatch existed invoked `wasm-merge` on a component binary, which Binaryen cannot parse.

You may invoke either tool directly. For modules:

```
wasm-merge --enable-multimemory --enable-simd --enable-bulk-memory --enable-bulk-memory-opt \
  --enable-nontrapping-float-to-int \
  <main.wasm> main <regexp.wasm> <module_name> ... \
  --rename-export-conflicts -o output.wasm
```

For components:

```
wac plug --plug <regexp1.wasm> --plug <regexp2.wasm> -o output.wasm <main.wasm>
```

**Composition is not merging.** `wasm-merge` produces ONE module whose regexp code reads the host's memory directly; `wac plug` produces a component holding two instances with two memories, where each call crosses the canonical ABI and copies its `list<u8>` input. Same command, different cost model — see [component.md](component.md).

**Several regexp artifacts in one call** works for both kinds, and both need a distinct name per artifact. Regexp *modules* need **distinct `import_module` values**: `compile` records each module's `import_module` in the module, `merge` names every module by its own record (a module built before the record existed gets the config's `import_module`, else its file name), and two modules under one name are refused ("a.wasm and b.wasm are both named "m": give each config its own import_module") — each module exports the setter its stubs hand the search block to under one fixed name, and a shared module name would bind every stub's setter call to one module only. Regexp *components* are matched by their WIT interface name, `regexped:<wit_package>/matcher`, which the socket genuinely imports — so composing several requires **distinct `wit_package` values**, or `wac` cannot tell which component should satisfy which import. `wac` reports that case with the same text a genuine name mismatch gives, so `merge` checks first: it runs `wasm-tools component wit` on every plug and refuses a repeated interface by name ("plugs a.wasm and b.wasm both export regexped:pkg/matcher"). A component merge therefore needs `wasm-tools` as well as `wac`, which every component pipeline already has, since a component cannot be compiled without it.

**Flags:**

| Flag | Default | Description |
|---|---|---|
| `--config` | `regexped.yaml` | YAML config file |
| `--main` | — | Host main WASM file **(required)** |
| `--output`, `-o` | config `output` | Output WASM file (must be a path; `-` is not accepted) |

**Positional arguments:** one or more regexp WASM files (at least one required).

Unlike `generate` and `compile`, `merge` does not accept `-` for stdout: the
value is handed straight to the external tool, which would create a file
literally named `-`.

**Config fields:**

| Field | Notes |
|---|---|
| `output` | Required unless `--output` is given. The merge target in both formats |
| `wasm_format` | Selects the tool: `module` → wasm-merge, `component` → wac |
| `wasm_merge_path` | Optional, `module` only. A file is the tool; a directory gets `wasm-merge` appended; relative to the config file. Omitted → `wasm-merge` in $PATH |
| `wac_path` | Optional, `component` only; the same rule for `wac` |
| `wasm_tools_path` | Optional, `component` only; the same rule for `wasm-tools`, which `merge` runs on each plug before composing (see above) |
| `import_module` | Optional, `module` only; module name passed to wasm-merge; defaults to basename of the regexp WASM |
| `wit_package` | `component` only; must be DISTINCT per regexp component when composing several (see above) |

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
