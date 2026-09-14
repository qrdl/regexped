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
    /// Why a matcher could not answer. No member means "no match".
    enum error-code { backtrack-overflow, malformed-cache, out-of-order }

    /// A scan in progress: the input crosses once, `next` steps it.
    resource find-github-token {
        constructor(input: list<u8>, start: u32);
        next: func() -> result<option<tuple<u32, u32>>, error-code>;
    }
}

world secrets {
    export matcher;
}
```

One config is one WIT package is one component. Names come from your own `_func`
values, kebab-cased:

| Config field | WIT shape |
|---|---|
| `match_func` | `func(input: list<u8>) -> result<option<u32>, error-code>` |
| `find_func` | `resource { constructor(input: list<u8>, start: u32); next: func() -> result<option<tuple<u32, u32>>, error-code> }` |
| `groups_func` | `resource { constructor(input: list<u8>, start: u32); next: func() -> result<list<option<tuple<u32, u32>>>, error-code> }` |

`match` answers `some(end)`. `find`'s `next` answers `some((start, end))` and
`none` when the scan is finished; `groups`' `next` answers one entry per capture
group, index 0 being the whole match, with `none` for a group that did not
participate, and an EMPTY list when the scan is finished. `start` is named
`start` rather than `from` because `from` is a WIT keyword.

### Why the two iterating exports are resources

`match` is one call and one answer. `find` and `groups` ITERATE, and a function
that iterates has to be handed the input again on every step — which the
canonical ABI copies. Scanning n bytes for m matches would copy `n × (m+1)`
bytes where the module stub copies none: a 1 MB log with 500 matches means
500 MB of copying.

A resource takes the input ONCE, in its constructor, and `next` carries only the
handle. That is the same move a set's `find` makes, and the measurement that
justified it there applies unchanged: 2,800 ns per stateless call against
230-400 ns for a resource `next` over a 4 KB input.

The generated Rust stub hides the resource completely — its public API is the
module stub's, iterator for iterator — so a Rust caller sees no difference. The
generated C stub keeps the handle inside the iterator struct and adds one
obligation, `<func>_free`; see [c-api.md](c-api.md). A consumer binding the WIT
DIRECTLY, with `bindgen!` or `jco`, calls the constructor and `next` itself.

### The error case is not "no match"

`error-code` is the only thing that distinguishes "there is no match" from
"I could not tell":

```
ok(none)                  — there is definitely no match at or after `start`
err(backtrack-overflow)   — the Backtracking engine ran out of frames and
                            ABANDONED part of the search space
err(malformed-cache)      — an overlapping set's answer cache had a header the
                            engine could not parse, so the scan is UNFINISHED
err(out-of-order)         — an overlapping set's scan was asked for a position
                            below where its answer cache was built: it went
                            backwards, so the scan is UNFINISHED
```

The last two are reachable only through a set's `find` resource, and a consumer
cannot provoke either: the constructor builds that header itself, and the
resource only ever moves forward. They are in the enum because the engine can
still report them, and reporting either AS a backtracking overflow would point at
the wrong thing entirely. The rule behind `out-of-order` — within one scan the
position must never go backwards — is a limitation of the module ABI, and its
detection there is best effort with no guarantee; see
[wasm.md](wasm.md#the-overlapping-answer-cache).

Treating any error as `ok(none)` is the dangerous mistake this type exists to
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
unset:            package regexped:secrets;          exports  regexped:secrets/matcher#match-x
wit_version: 2.3.0  package regexped:secrets@2.3.0;  exports  regexped:secrets/matcher@2.3.0#match-x
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

// `find` is a RESOURCE: construct once with the input, then step it.
let res = matcher.find_github_token();
let scan = res.call_constructor(&mut store, input, 0)?;
loop {
    match res.call_next(&mut store, scan)? {
        Ok(Some((start, end))) => println!("match at {start}..{end}"),
        Ok(None) => break,                       // the scan is finished
        Err(e) => { eprintln!("cannot decide: {e:?}"); break; }
    }
}
res.call_drop(&mut store, scan)?;                // ends the scan, frees its state
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
clang --target=wasm32-wasi -nostdlib -DRX_SET_CACHE=0 -Wl,--no-entry -o core.wasm your.c stub.c
wasm-tools component embed wit core.wasm --world <name>-consumer -o embedded.wasm
wasm-tools component new embedded.wasm -o guest.wasm
regexped merge --config=regexped.yaml --main=guest.wasm regexps.wasm
```

Four things to know:

- **The two `wasm-tools` lines are yours, not regexped's**, and only the wasip1
  target needs them — see [Why the wasip1 target needs two extra
  commands](#why-the-wasip1-target-needs-two-extra-commands) below.

- **Call `<func>_free(&iter)` on every exit from a find or groups loop** — each
  `break`, `return` and `goto`, not only the last — and before initialising the
  same iterator again. The scan lives inside the regexp component behind a
  resource handle, so an abandoned iterator strands its input copy and state for
  the life of the process, and `_init` only writes the struct, so it cannot
  release a handle it was never told about. The same call is a no-op under
  `wasm_format: module`, which is what lets one source build both ways.
- **Add your own exports** to the generated `wit/consumer.wit`. It arrives with
  the import declared and nothing exported, and a component with no exports can
  be composed but not run.
- **`component embed` needs the `wit` DIRECTORY**, not one file: that is how it
  finds `deps/`.

If a pattern exports groups, or a set returns a list, the stub also defines
`cabi_realloc`, because the canonical ABI allocates a returned list in *your*
memory. It is a bump allocator that the generated wrappers mark and restore
around their own calls, sized by `REGEXPED_CABI_HEAP_BYTES` (256 KB default) —
raise that if a pattern has a very large number of groups. See
[c-api.md](c-api.md).

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

`wac` is found through `wac_path:` in the config, else in `$PATH` — the rule all
three tool keys share: a file is the tool itself (so it may carry any name), a
directory gets the tool name appended, a relative path is relative to the config
file, and `~` / `~/dir` expand to the home directory. No environment variable is
read. Before composing, `merge` runs `wasm-tools component wit` on every plug, so
a component merge needs `wasm-tools` too (`wasm_tools_path:`, else `$PATH`). `output:` in the config names the result; `--output` overrides it,
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
`wit_package` values.** `merge` checks this before `wac` runs and names both
plugs and the interface ("plugs a.wasm and b.wasm both export
regexped:pkg/matcher"); `wac` alone reports it with the text a genuine name
mismatch gives.

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

`next` reports **one** match, so something has to drive it. The generated stubs
do, and one rule is worth knowing about if you ever write the loop yourself — as
a WIT-only host must:

- **Go's adjacent-empty rule** — an empty match beginning exactly where the
  previous REPORTED match ended is suppressed. Omit it and `(a?)` over `"ab"`
  gives you `(0,1),(1,1),(2,2)` where every regexped stub gives `(0,1),(2,2)`.
  Same pattern, same input, different answers.

The other rule a module-format caller has to write — the ADVANCE,
`start = if end > start { end } else { start + 1 }`, without whose second arm a
zero-length match spins for ever — is the resource's own now. It steps itself,
so there is no position to carry and no way to get that wrong.

The adjacent-empty rule stays OUTSIDE, in the consumer, and that placement is
deliberate: it decides what is REPORTED rather than where the scan goes, so the
raw resource answers exactly the matches the raw module export does, and a stub
subtracts from that.

Handing the constructor the **whole** input is not an inefficiency to optimise
away: `\b`, `\B` and `(?m:^)` are judged against the real preceding byte, so a
sliced input would silently change the answer at the seam. `start` bounds where
the first step searches from; it never truncates what the engine sees behind it.

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
    enum error-code { backtrack-overflow, malformed-cache, out-of-order }
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
empty list means the scan is finished. The input crosses into the component
ONCE, through the canonical ABI's own lowering, and the constructor takes over the
block it was lowered into rather than copying it again: the input is held for the
scanner's lifetime and released by `[dtor]`. That single crossing is the point —
a stateless per-position export would copy the whole input on every call, and
measurement put that at 2800 ns against 230-400 ns for a resource `next` on a
4 KB input.

Two scans can be in flight at once, each with its own handle and its own state —
the same property the module-format C scanner has.

**Dropping the handle is what frees the scan.** Rust hides that entirely: the
iterator owns the handle and drops it. C cannot, because its scanner has no
destructor to hang the drop on — which is why `<func>_free` exists in BOTH
formats: for a module it frees an overlapping scanner's answer cache, if it
owns one, and here it drops the handle, which is mandatory. See
[c-api.md](c-api.md#sets).

### What a set costs here

- `overlapping: true` sets get the ANSWER CACHE here as everywhere else, so an
  overlapping drive is linear rather than quadratic. A component consumer has no
  pointer to hand in and nothing to free, so the `find` resource's CONSTRUCTOR
  reserves the region and `[dtor]` releases it with the input block and the
  gates. You never see it.

  It is sized from the input length at construction: linear in it up to a 64 MiB
  budget, and the square root of it above that — a few hundred kilobytes for a
  ten-megabyte scan. A region over budget is simply declined and the drive
  walks, with identical answers.
- Every `next` is a cross-component call, but NOT a copy of the input: the input
  crossed once, when the scanner was constructed.
- The `_all` pair allocates a list of ids per call, bounded by the number of
  matching patterns rather than by the input.

## Costs

- **Every call copies the input** into guest memory, as the canonical ABI
  requires — but an ITERATING export is a resource, so that is once per SCAN
  rather than once per match, for a set's `find` and for a single pattern's
  `find` and `groups` alike. `match` and the set's stateless capabilities are one
  call and so one copy. The same per-call copy is true of the JS/TS module stubs
  today; it is not true of the Rust/Go/C embedded path, which shares the host's
  memory.
- A few allocations per call, each freed by the post-return or the destructor:
  the result area alone for `match`, `find` and the `any` pair; three for
  `groups` (the area, the slots and the element list); two for a narrow `_all`
  and three for a wide one, whose bitmap is allocated too; two for `next`; and
  two or three for the constructor — its state and gate array, plus the cache
  when one is offered — with one more, a copy of the input, only when it cannot
  take over the lowered block. Negligible against a scan of any real length.
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
and one adapter per exported function — a constructor, a `next` and a destructor
for each resource — that allocates a result area, calls the existing body, and
translates the `-1` / `-2` / `-4` / `-6` sentinels into the discriminated layouts.
Because they are appended, no pattern function is reordered; each resource adds one
imported `[resource-new]` builtin, which shifts every defined function index by the
same amount. A `wasm_format: module` build is byte-for-byte what it always was.

`wasm-tools` then does the wrapping:

```
wasm-tools component embed <wit> <core> --world <world> -o <tmp>
wasm-tools component new <tmp> -o <out>
```

It is found through `wasm_tools_path:` in the config, else in `$PATH`, and it is a
hard requirement of this format: a `module` build needs no external binary,
a `component` build cannot finish without this one. Composing later needs `wac`
the same way. Both ship in the Docker image — see [docker.md](docker.md).

The raw core exports (`find_github_token` and friends) are kept alongside the
canonical ones. They are unreachable from a component host, but they let
`wasm-tools component unbundle` produce a core module the module-format tooling
can still drive, which is useful when debugging.
