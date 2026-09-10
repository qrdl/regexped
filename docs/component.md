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
wac plug your.wasm --plug regexps.wasm -o composed.wasm
wasmtime run composed.wasm
```

Your `Cargo.toml` needs `wit-bindgen`. That is the one place parity does not
hold, and it is not a choice: `wasm32-wasip2` refuses a hand-written import,
because a component consumer needs component-type metadata that only a binding
generator embeds. The generated stub carries that macro and hides it behind the
familiar API. Until `wac plug` runs, the guest has an unsatisfied import and will
not instantiate — the analogue of forgetting `regexped merge`.

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
wac plug guest.wasm --plug regexps.wasm -o composed.wasm
```

Two things to know:

- **Add your own exports** to the generated `wit/consumer.wit`. It arrives with
  the import declared and nothing exported, and a component with no exports can
  be composed but not run.
- **`component embed` needs the `wit` DIRECTORY**, not one file: that is how it
  finds `deps/`.

If a pattern exports groups, the stub also defines `cabi_realloc`, because the
canonical ABI allocates a returned list in *your* memory. It is a bump allocator
reset per call, sized by `REGEXPED_CABI_HEAP_BYTES` (8 KB default) — raise that
if a pattern has a very large number of groups.

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

## Costs

- **Every call copies the input** into guest memory, as the canonical ABI
  requires. The same is true of the JS/TS module stubs today; it is not true of
  the Rust/Go/C embedded path, which shares the host's memory.
- One allocation per call for the result area, two more for `groups`. Negligible
  against a scan of any real length.
- Memory grows to fit a large input and is never given back — the per-call reset
  moves a bump pointer, it does not shrink the memory.
- The component is roughly 2 KB larger than the core module it wraps.

## Not yet supported

| | Status |
|---|---|
| Pattern **sets** | Refused at load: "sets are not supported for wasm_format: component yet". A stateless component export would have to run the whole drive internally — the gate array, the advance loop, the overflow retry — which the stubs own today. |
| `go` / `as` / `js` / `ts` stubs | Not component targets, permanently. Stock Go has no wasip2 target, so a Go component stub would have to be TinyGo; AssemblyScript has no planned route; and no JavaScript runtime loads a component — `WebAssembly.instantiate` accepts core modules only — so a JS consumer needs `jco transpile`, whose output is a core module plus glue, i.e. where `wasm_format: module` already starts. |
| Batch exports (`hints: [batch-find]`) | Not exported from the component. |

## How it is built

The compiler emits the core module exactly as it does for `wasm_format: module` —
same engines, same bodies, same signatures — and **appends** the canonical-ABI
machinery: a `cabi_realloc` bump allocator, one shared post-return that resets it,
and one adapter per exported function that allocates a result area, calls the
existing body, and translates the `-1` / `-2` sentinels into the discriminated
layouts. Because they are appended, no pattern function moves, and a
`wasm_format: module` build is byte-for-byte what it always was.

`wasm-tools` then does the wrapping:

```
wasm-tools component embed <wit> <core> --world <world> -o <tmp>
wasm-tools component new <tmp> -o <out>
```

The raw core exports (`find_github_token` and friends) are kept alongside the
canonical ones. They are unreachable from a component host, but they let
`wasm-tools component unbundle` produce a core module the module-format tooling
can still drive, which is useful when debugging.
