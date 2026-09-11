# WASM Component Model

Regexped emits two kinds of output. The default is a core WASM module, documented
in [wasm.md](wasm.md) and consumed through the generated stubs. Setting
`wasm_format: component` instead produces a **Component Model component** with a
generated **WIT** interface, loadable by any component runtime — wasmtime,
`jco`-transpiled JavaScript, or a host using `wasmtime::component::bindgen!`.

```yaml
wasm_format:   component
import_module: "secrets"
wasm_file:     "secrets.wasm"

regexps:
  - pattern:   'ghp_[A-Za-z0-9]{36}'
    find_func: "find_github_token"
```

```
$ regexped compile
$ ls
secrets.wasm   secrets.wit
```

The `.wit` is written beside the binary because every consumer toolchain needs
the interface text, and a component does not hand it over in a form they take.

## What you get

```wit
package regexped:secrets;

interface matcher {
    /// The Backtracking engine exhausted its frame budget; the answer is unknown.
    enum error-code { backtrack-overflow }

    /// Leftmost match starting at or after `start`. Positions are absolute.
    find-github-token: func(input: list<u8>, start: u32) -> result<option<tuple<u32, u32>>, error-code>;
}

world secrets {
    export matcher;
}
```

One config is one WIT package is one component. Function names come from your own
`_func` values, kebab-cased:

| Config field | WIT signature |
|---|---|
| `match_func` | `func(input: list<u8>) -> result<option<u32>, error-code>` |
| `find_func` | `func(input: list<u8>, start: u32) -> result<option<tuple<u32, u32>>, error-code>` |
| `groups_func` | `func(input: list<u8>, start: u32) -> result<option<list<option<tuple<u32, u32>>>>, error-code>` |

`match` answers `some(end)`; `find` answers `some((start, end))`; `groups` answers
one entry per capture group, index 0 being the whole match, with `none` for a
group that did not participate. `start` is named `start` rather than `from`
because `from` is a WIT keyword.

### The error case is not "no match"

`error-code` has one member, and it is the only thing that distinguishes
"there is no match" from "I could not tell":

```
ok(none)                  — there is definitely no match at or after `start`
err(backtrack-overflow)   — the Backtracking engine ran out of frames and
                            ABANDONED part of the search space
```

Treating the second as the first is the dangerous mistake this type exists to
prevent — a secret scanner that reports "clean" because the engine gave up is
worse than one that fails. Only patterns compiled to the Backtracking engine can
produce it (see [engines.md](engines.md)), but every function's return type
carries it, so the ABI is uniform.

## Naming

Five names come from your config, and they have incompatible rules, so each has
its own optional key. All default so that a config setting none of them behaves
exactly as it always has.

| Key | Role | Default |
|---|---|---|
| `import_module` | the WASM import-module name — a **wire string** | — |
| `rust_module` | the Rust `pub mod` identifier | `import_module` |
| `go_package` | the Go `package` identifier | `import_module` |
| `wit_package` | the WIT package name | `kebab(import_module)` |
| `wit_world` | the WIT world name | `wit_package` |

WIT identifiers are `[a-z][a-z0-9]*(-[a-z][a-z0-9]*)*` — hyphens required,
underscores illegal — which Rust and Go forbid outright, so `import_module:
"url_ipv6"` becomes the WIT package `url-ipv6`. A name that cannot be represented
(`_x`, `x__y`, `9x`, `my.mod`) is an error telling you to set `wit_package`,
never a silent rename: renaming would change which export a caller reaches.

The **world** name is worth its own key because it is the only one here that no
ABI depends on. It is absent from every export name and merely names the
consumer's generated bindings — `wit-bindgen c` writes `<world>.c` / `<world>.h`,
and `bindgen!` produces a struct of that name — so you can change it freely,
whereas changing the package renames every export.

### Versioning

`wit_version` is optional, and **unset means no version at all**:

```
unset:            package regexped:secrets;          exports  regexped:secrets/matcher#find-x
wit_version: 2.3.0  package regexped:secrets@2.3.0;  exports  regexped:secrets@2.3.0/matcher#find-x
```

Because the version is part of every export name, adding, removing or changing it
**breaks every consumer** — their build fails on a missing import. That is
deliberate: it is opt-in, one-time, and loud. Set it if you want a compatibility
promise your users can check with `wasm-tools component semver-check`; leave it
unset and the interface simply has no versioning story.

## Consuming it

### Rust host (wasmtime)

```rust
wasmtime::component::bindgen!({ path: "secrets.wit", world: "secrets" });

let engine = Engine::default();
let component = Component::from_file(&engine, "secrets.wasm")?;
let mut store = Store::new(&engine, ());
let secrets = Secrets::instantiate(&mut store, &component, &Linker::new(&engine))?;
let matcher = secrets.regexped_secrets_matcher();

match matcher.call_find_github_token(&mut store, input, 0)? {
    Ok(Some((start, end))) => println!("match at {start}..{end}"),
    Ok(None) => println!("no match"),
    Err(ErrorCode::BacktrackOverflow) => eprintln!("cannot decide"),
}
```

That is the **WIT-only** route: `stub_type` unset, no generated stub, the host
binding for itself. It stays supported, and it is the right route for a host.

### Rust guest, with a generated stub

The route to prefer when your own code is compiled to WASM. `stub_type: rust`
under `component` produces a stub whose **public API is identical** to the
module-format one, so calling code does not change:

```rust
include!("stubs.rs");

for m in secrets::find_github_token(input, 0) {
    let (start, end) = m?;          // Err is BacktrackOverflow, not "no match"
    println!("{start}..{end}");
}
```

The build differs, not the API:

```sh
regexped compile          # component + sibling .wit
regexped generate         # stubs.rs
cargo build --target wasm32-wasip2       # your code, itself a component
regexped merge --config=regexped.yaml --main=your.wasm regexps.wasm
wasmtime run composed.wasm               # the `output:` from your config
```

Your `Cargo.toml` needs `wit-bindgen`. That is the one place parity does not
hold, and it is not a choice: `wasm32-wasip2` refuses a hand-written import,
because a component consumer needs component-type metadata that only a binding
generator embeds. The generated stub carries that macro and hides it behind the
familiar API. Until the merge step runs, the guest has an unsatisfied import and
will not instantiate.

`examples/wasmtime/rust/secrets` 🧩 is this route end to end.

### C guest, with a generated stub

Same API as the module-format C stub — `rx_match_t`, `rx_group_t`, caller-owned
`_init`/`_next` iterators, group-index constants — because the header comes from
the same generator. And unlike Rust, **no third-party dependency**: C builds a
plain core module, so the component metadata is attached afterwards.

```sh
regexped compile          # component + sibling .wit
regexped generate         # stub.h, stub.c, and a wit/ directory
clang --target=wasm32-wasi -nostdlib -Wl,--no-entry -o core.wasm your.c stub.c
wasm-tools component embed wit core.wasm --world <name>-consumer -o embedded.wasm
wasm-tools component new embedded.wasm -o guest.wasm
regexped merge --config=regexped.yaml --main=guest.wasm regexps.wasm
```

Three things to know:

- **The two `wasm-tools` lines are yours, not regexped's**, and only the wasip1
  target needs them — see [Why the wasip1 target needs two extra
  commands](#why-the-wasip1-target-needs-two-extra-commands) below.

- **Add your own exports** to the generated `wit/consumer.wit`. It arrives with
  the import declared and nothing exported, and a component with no exports can
  be composed but not run.
- **`component embed` needs the `wit` DIRECTORY**, not one file: that is how it
  finds `deps/`.

If a pattern exports groups, the stub also defines `cabi_realloc`, because the
canonical ABI allocates a returned list in *your* memory. It is a bump allocator
reset per call, sized by `REGEXPED_CABI_HEAP_BYTES` (8 KB default) — raise that
if a pattern has a very large number of groups.

### Composing — `regexped merge`

The last step is the same command a module build runs. `merge` dispatches on
`wasm_format` and calls the right tool, so the command a user types does not
depend on the output kind:

```sh
regexped merge --config=regexped.yaml --main=guest.wasm regexps.wasm
```

| `wasm_format` | tool | `--main` is |
|---|---|---|
| `module` | `wasm-merge` | the host module |
| `component` | `wac plug` | the **socket** — the component with the unsatisfied import |

`wac` is resolved as config `wac:` → `$WAC` → `$PATH`, the same order the other
two tools use. `output:` in the config names the result; `--output` overrides it,
which is what a directory building the guest twice needs.

**Composing is not merging.** `wasm-merge` produces ONE module whose regexp code
reads the host's memory directly. `wac plug` produces a component holding two
instances with two memories, and every call crosses the canonical ABI and copies
its input. Same command, different cost model — see [Costs](#costs).

**Several regexp components in one call** works, with one asymmetry against the
module format. Regexp *modules* may all share an `import_module` name, because
nothing imports it — it is a label with no consumers. Regexp *components* are
matched by their interface name, `regexped:<wit_package>/matcher`, which the
socket genuinely imports, so two components built from configs sharing a
`wit_package` export the same interface and `wac` cannot tell which should
satisfy the import. **Composing several therefore requires distinct
`wit_package` values.**

### Why the wasip1 target needs two extra commands

The C recipe above runs `wasm-tools component embed` and `component new` on
*your* compiled code. That is not something regexped does for you, and it is not
needed on every route — it depends on what your compiler emits:

| how you build your own code | what comes out | wrap needed |
|---|---|---|
| Rust `wasm32-wasip2` | a component | no — rustc links it through `wasm-component-ld` |
| C `--target=wasm32-wasip2` | a component | no — clang links it through `wasm-component-ld` |
| **C `--target=wasm32-wasip1`** | a **core module** | **yes** |

Only the last row needs the wrap, and regexped does not do it: the input is your
own compiled code, which regexped never sees. Run it yourself:

```sh
wasm-tools component embed <wit-dir> <guest-core.wasm> --world <world>-consumer -o embedded.wasm
wasm-tools component new embedded.wasm --adapt wasi_snapshot_preview1=<adapter>.wasm -o guest.wasm
```

- `<wit-dir>` is the `wit/` directory generated beside the C stub. It must be the
  DIRECTORY, not one file — that is how `embed` resolves `deps/`.
- `<world>-consumer` is your `wit_world` (default: `wit_package`) with the
  `-consumer` suffix regexped appends.
- `<adapter>.wasm` is `wasi_snapshot_preview1.command.wasm`, from the
  [wasmtime releases](https://github.com/bytecodealliance/wasmtime/releases). It
  bridges the `wasi_snapshot_preview1` imports your code makes to `wasi:cli`.
  A `reactor` build of the adapter is the one to use for a library with no
  `main`.

`examples/wasmtime/c/url-parts` 🧩 builds the same `main.c` three ways — module,
wasip1 component, wasip2 component — with the two wrap commands appearing only in
the wasip1 target.

### Iteration, and the rule a hand-written loop gets wrong

`find` reports **one** match, so something has to drive it. The generated stubs
do, and they carry two rules worth knowing about if you ever write the loop
yourself — as a WIT-only host must:

- **the advance rule** — `start = if end > start { end } else { start + 1 }`;
  without the second arm a zero-length match spins for ever;
- **Go's adjacent-empty rule** — an empty match beginning exactly where the
  previous REPORTED match ended is suppressed. Omit it and `(a?)` over `"ab"`
  gives you `(0,1),(1,1),(2,2)` where every regexped stub gives `(0,1),(2,2)`.
  Same pattern, same input, different answers.

Passing the **whole** input every time is not an inefficiency to optimise away:
`\b`, `\B` and `(?m:^)` are judged against the real preceding byte, so a sliced
input would silently change the answer at the seam.

### Other languages

`wit-bindgen` generates **guest** bindings — code for a component that
*implements* an interface — so it is not what a host uses.

For a **JavaScript or TypeScript** consumer, prefer `wasm_format: module` and the
generated JS/TS stub. A component can be consumed from JS only through
`jco transpile`, which emits a core module plus canonical-ABI glue — the core
module being exactly what the `module` format produces directly, so the component
route costs an extra tool and build step to arrive at the same place. `stub_type:
js`/`ts` is therefore refused under `component`.

## Sets

A `sets:` block becomes a SECOND interface, `sets`, beside `matcher`. The world
exports only the interfaces that exist, so a config of only sets gets no empty
`matcher` and vice versa.

```wit
interface sets {
    enum error-code { backtrack-overflow }
    record set-match { id: u32, start: u32, end: u32 }

    which-matches: func(input: list<u8>) -> result<option<u32>, error-code>;
    all-matches:   func(input: list<u8>) -> result<list<u32>, error-code>;
    any-hit:       func(input: list<u8>, start: u32) -> result<option<u32>, error-code>;
    all-hits:      func(input: list<u8>, start: u32) -> result<list<u32>, error-code>;

    resource scan-secrets {
        constructor(input: list<u8>, start: u32);
        next: func() -> result<list<set-match>, error-code>;
    }
}
```

The names are YOUR names — `match_any: which_matches` becomes `which-matches` —
kebab-cased, exactly as for single patterns. The `find:` name becomes a resource
rather than a function, for the reason below.

**`error-code` is declared again here rather than shared with `matcher`.** A
sets-only config would otherwise have to export an interface holding nothing but
that enum. Both generated stubs map the two enums onto one error type, so a
consumer never sees the duplication.

### `_all` returns ids, not a bitmask

The raw ABI has two forms — an i64 bitmask up to 64 patterns, and a count plus a
caller-owned bitmap above it — and neither crosses a component boundary: the
consumer cannot supply the bitmap. Both lift to `list<u32>` of global pattern
ids, ascending.

That is measured, not assumed. Handing the bitmap over instead was slower in all
twelve shapes tried (3 to 4096 patterns, 1 to 2048 matching), because the bit
scan is the cost and a bitmap does not avoid it — it moves it to the consumer and
adds the transfer. A shape that varied with pattern count was rejected outright:
adding a 65th pattern would silently change the interface every consumer compiled
against.

### `find` is a resource, and that is what the gate array costs

The module ABI makes `find` resumable by giving the CALLER the state: a gate
array of `ID_SPACE` u32s, plus the position. A component consumer has no way to
own memory the regexp component reads, so the state moves inside, behind a
handle:

```wit
resource <find-name> {
    constructor(input: list<u8>, start: u32);
    next: func() -> result<list<set-match>, error-code>;
}
```

`next` answers the matches at ONE position — they all share a start — and an
empty list means the scan is finished. The constructor copies the input in ONCE,
which is the point: a stateless per-position export would copy the whole input on
every call, and measurement put that at 2800 ns against 230-400 ns for a
resource `next` on a 4 KB input.

Two scans can be in flight at once, each with its own handle and its own state —
the same property the module-format C scanner has.

**Dropping the handle is what frees the scan.** Rust hides that entirely: the
iterator owns the handle and drops it. C cannot, because its scanner has no
destructor to hang the drop on — which is why `<func>_free` exists in BOTH
formats, a no-op for a module and mandatory here. See
[c-api.md](c-api.md#sets).

### What a set costs here

- `overlapping: true` sets are quadratic per drive by design, and the component
  form has no answer cache — so it behaves like a C or Rust MODULE consumer,
  which has none either. Only the JS/TS module stubs reserve one. If you need
  that mitigation, use `wasm_format: module`.
- Every `next` is a cross-component call, but NOT a copy of the input: the
  constructor did that once.
- The `_all` pair allocates a list of ids per call, bounded by the number of
  matching patterns rather than by the input.

## Costs

- **Every call copies the input** into guest memory, as the canonical ABI
  requires. The same is true of the JS/TS module stubs today; it is not true of
  the Rust/Go/C embedded path, which shares the host's memory.
- One allocation per call for the result area, two more for `groups`. Negligible
  against a scan of any real length.
- Memory grows to fit a large input and is never given back to the OS —
  `memory.grow` is one-way. It IS reused: the allocator keeps per-size-class free
  lists, and the post-return returns the call's blocks to them, so a repeated
  call does not grow the component at all. A block is reused only for a request
  of its own power-of-two class, which bounds the waste at 2x per allocation and
  is what makes repeated calls flat.
- The component is roughly 2 KB larger than the core module it wraps.

## Not yet supported

| | Status |
|---|---|
| Batch exports on a set (`hints: [batch-find]`) | Refused at load. Batching amortises host crossings for a caller that intends to consume everything, and the interface deliberately exposes one position per call through the find resource. It is refused rather than ignored because the user asked for a second entry point. |
| `go` / `as` / `js` / `ts` stubs | Not component targets, permanently. Stock Go has no wasip2 target, so a Go component stub would have to be TinyGo; AssemblyScript has no planned route; and no JavaScript runtime loads a component — `WebAssembly.instantiate` accepts core modules only — so a JS consumer needs `jco transpile`, whose output is a core module plus glue, i.e. where `wasm_format: module` already starts. |

## How it is built

The compiler emits the core module exactly as it does for `wasm_format: module` —
same engines, same bodies, same signatures — and **appends** the canonical-ABI
machinery: a `cabi_realloc` with per-size-class free lists, one shared
post-return that returns the call's blocks to them,
and one adapter per exported function that allocates a result area, calls the
existing body, and translates the `-1` / `-2` sentinels into the discriminated
layouts. Because they are appended, no pattern function moves, and a
`wasm_format: module` build is byte-for-byte what it always was.

`wasm-tools` then does the wrapping:

```
wasm-tools component embed <wit> <core> --world <world> -o <tmp>
wasm-tools component new <tmp> -o <out>
```

It is resolved as config `wasm_tools:` → `$WASM_TOOLS` → `$PATH`, and it is a
hard requirement of this format: a `module` build needs no external binary,
a `component` build cannot finish without this one. Composing later needs `wac`
the same way. Both ship in the Docker image — see [docker.md](docker.md).

The raw core exports (`find_github_token` and friends) are kept alongside the
canonical ones. They are unreachable from a component host, but they let
`wasm-tools component unbundle` produce a core module the module-format tooling
can still drive, which is useful when debugging.
