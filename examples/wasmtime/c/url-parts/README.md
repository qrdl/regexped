# url-parts — URL parsing into components

Finds all URLs in text and parses each into named capture groups using the **TDFA engine** — a tagged DFA with inline capture slot tracking.

Groups extracted: `scheme`, `host`, `port`, `path`, `query`, `fragment`.

This example builds **three ways** from one unchanged `main.c` — a core WASM
module, and a **Component Model component** 🧩 by either of two routes. All three
print identical output. See [Three build options](#three-build-options).

## Prerequisites

- `regexped` binary (run `make` in the repo root)
- `clang-19` with `wasm-ld` (`apt install clang-19 lld-19`)
- [wasm-merge](https://github.com/WebAssembly/binaryen) — module build
- [wasmtime](https://wasmtime.dev)

For the component builds additionally:

- [wac](https://github.com/bytecodealliance/wac) — composes the two components
  (both routes)
- **`make component`** (wasip1 route) also needs
  [wasm-tools](https://github.com/bytecodealliance/wasm-tools) and the **wasip1
  adapter** (`wasi_snapshot_preview1.command.wasm`). `main.c` talks
  `wasi_snapshot_preview1` directly while a component speaks `wasi:cli`, so the
  adapter bridges them. The Makefile finds the copy shipped in the
  `wasi-preview1-component-adapter-provider` crate; point `ADAPTER=` at your own
  otherwise.
- **`make wasip2`** route instead needs
  [`wit-bindgen`](https://github.com/bytecodealliance/wit-bindgen) and
  `wasm-component-ld`. rustup ships the latter inside the toolchain rather than on
  PATH; override `WASM_COMPONENT_LD_DIR=` if yours lives elsewhere.

No libc or WASI sysroot required — the example uses direct WASI imports.

## Run

```sh
make
```

Expected output:
```
=== single URL ===
URL:
  scheme     = https
  host       = example.com
  port       = 8080
  path       = /path/to/page
  query      = q=1&r=2
  fragment   = section
```

## Build pipeline

```
regexped generate   →  generate C header stub (stub.h)
clang               →  compile C to WASM (wasm32-wasi, no sysroot)
regexped compile    →  compile regexp pattern to WASM
regexped merge      →  merge C WASM + regexp WASM into final binary
wasmtime run        →  execute
```

## Three build options

```sh
make               # 1. core WASM module, linked with wasm-merge
make component-run # 2. component, wasip1 route: clang -> embed -> new -> wac
make wasip2-run    # 3. component, wasip2 route: clang wraps at link time -> wac
```

All three print **identical output**, and `main.c` is compiled **unchanged** for
every one of them. That is the point of the example: the generated stub's public
API does not depend on the output kind or the route, so only the build differs.

Options 2 and 3 produce the **same kind of artefact** — a component. They differ
only in *when* the component wrapping happens and therefore in what tools you
need.

| | 1. module | 2. component (wasip1) | 3. component (wasip2) |
|---|---|---|---|
| config | `regexped.yaml` | `regexped-component.yaml` | same as 2 |
| artefacts in | this directory | `component/` | `wasip2/` (reusing 2's stub and WIT) |
| clang target | `wasm32-wasi` | `wasm32-wasi` | `wasm32-wasip2` |
| linker | `wasm-ld` | `wasm-ld` | `wasm-component-ld` |
| wrapping | — | `wasm-tools component embed` + `new`, after linking | at LINK time, by clang |
| WASI bridging | native | `--adapt` with the wasip1 adapter | bundled in the linker |
| extra tool | wasm-merge | wasm-tools + the adapter | **wit-bindgen** |
| link step | `regexped merge` (→ wasm-merge) | `regexped merge` (→ wac) | `regexped merge` (→ wac) |

**Why route 2 exists at all**, given 3 is fewer steps: route 3 needs the
component-type metadata to be *in the objects before the linker runs*, which means
linking `wit-bindgen c`'s `*_component_type.o`. regexped cannot emit a wasm object
file, so route 3 requires a code generator that route 2 does not — route 2 attaches
the same metadata *after* linking, with `wasm-tools component embed`. Route 3 uses
wit-bindgen for that one object and **discards its `.c`/`.h`**: the bindings come
from regexped's stub either way.

The stub itself is byte-identical between routes 2 and 3. Nothing in regexped's
output chooses a route; your Makefile does.

**The adapter is only needed because `main.c` uses preview1 WASI imports directly**
(`args_get`, `fd_write`, `proc_exit`, `_start`). A component that exports a plain
function instead of `_start` needs no adapter at all.

One thing worth knowing if you write your own consumer: the generated
`cabi_realloc` is the **whole component's** allocator, not the stub's private
scratch — the wasip1 adapter calls it too. The stub therefore saves and restores a
bump mark around its own call rather than resetting, and its heap is sized
(`REGEXPED_CABI_HEAP_BYTES`, 256 KB) for the adapter's stack. Define it smaller for
a component that pulls in no adapter.
