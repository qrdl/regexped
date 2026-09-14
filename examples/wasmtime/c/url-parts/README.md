# url-parts — URL parsing into components

Finds all URLs in text and parses each into named capture groups using the **TDFA engine** — a tagged DFA with inline capture slot tracking.

Groups extracted: `scheme`, `host`, `port`, `path`, `query`, `fragment`.

This example builds **three ways** from one unchanged `main.c` — a core WASM
module, and a **Component Model component** 🧩 by either of two routes. All three
print identical output. See [Three build options](#three-build-options).

## Prerequisites

The Makefile install nothing. Install these first:

| Tool | Routes | How to install |
|---|---|---|
| `regexped` | all | run `make` in the repo root |
| `clang-19` with `wasm-ld` | all | `apt install clang-19 lld-19`, or your distribution's equivalent |
| `wasmtime` | all (the running targets) | `curl https://wasmtime.dev/install.sh -sSf \| bash` — see [wasmtime.dev](https://wasmtime.dev) |
| `wasm-merge` | 1 | from [Binaryen](https://github.com/WebAssembly/binaryen/releases): unpack a release and put its `bin/` on `PATH` |
| `wasm-tools` | 2, 3 | a [release](https://github.com/bytecodealliance/wasm-tools/releases) on `PATH`, or `cargo install --locked wasm-tools` |
| `wac` | 2, 3 | a [release](https://github.com/bytecodealliance/wac/releases) (the `wac-cli-<platform>` binary, renamed to `wac`) on `PATH`, or `cargo install --locked wac-cli` |
| the wasip1 adapter | 2 | download `wasi_snapshot_preview1.command.wasm` from a [wasmtime release](https://github.com/bytecodealliance/wasmtime/releases) and pass `ADAPTER=/path/to/it` |
| `wit-bindgen` CLI | 3 | `cargo install --locked wit-bindgen-cli`, or a [release](https://github.com/bytecodealliance/wit-bindgen/releases) on `PATH` |
| `wasm-component-ld` | 3 | ships with the Rust toolchain: install Rust with [rustup](https://rustup.rs) |

The example builds three ways; see [Three build options](#three-build-options).
Route 1 is the default:

| Route | Targets | Needs |
|---|---|---|
| 1. module (default) | `make` builds `final.wasm`; `make run` also runs it. `make generate`, `make build`, `make compile` and `make merge` are the individual steps | `regexped`, clang, `wasm-merge`; `wasmtime` for `run` |
| 2. component, wasip1 | `make component` builds `component/composed.wasm`; `make component-run` also runs it | `regexped`, clang, `wasm-tools`, `wac`, the adapter; `wasmtime` for `component-run` |
| 3. component, wasip2 | `make wasip2` builds `wasip2/composed.wasm`; `make wasip2-run` also runs it | `regexped`, clang, `wasm-tools`, `wac`, `wit-bindgen`, `wasm-component-ld`; `wasmtime` for `wasip2-run` |
| — | `make clean` removes the outputs of all three | — |

In route 2, `regexped compile` wraps the component with `wasm-tools`, the
Makefile runs `wasm-tools component embed` and `component new`, and
`regexped merge` composes with `wac` after checking each component's exports
with `wasm-tools`. Route 3 uses `wasm-tools` and `wac` the same way through
`regexped`, and `wit-bindgen c` for one object file.

**The wasip1 adapter** (route 2) bridges `main.c`, which talks
`wasi_snapshot_preview1` directly, to a component, which speaks `wasi:cli`. If
`ADAPTER` is not set, the Makefile looks for the copy shipped in the
`wasi-preview1-component-adapter-provider` crate in your cargo registry.

**`wasm-component-ld`** (route 3) is the linker clang uses for `wasm32-wasip2`.
rustup ships it inside the toolchain rather than on `PATH`, and the Makefile
finds it there; override `WASM_COMPONENT_LD_DIR=` if yours lives elsewhere.

`wasm-merge`, `wasm-tools` and `wac` are looked up on `PATH` (a config can name
them with `wasm_merge_path:`, `wasm_tools_path:` and `wac_path:` instead). No libc
or WASI sysroot is required — the example uses direct WASI imports.

## Run

```sh
make               # 1. core WASM module (build only)
make run           # 1. core WASM module
make component-run # 2. component, wasip1 route
make wasip2-run    # 3. component, wasip2 route
```

The three running targets print the same output:

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

## Build pipeline (route 1)

```
regexped generate   →  generate C header stub (stub.h)
clang               →  compile C to WASM (wasm32-wasi, no sysroot)
regexped compile    →  compile regexp pattern to WASM
regexped merge      →  merge C WASM + regexp WASM into final binary
wasmtime run        →  execute
```

## Three build options

```sh
make run           # 1. core WASM module, linked with wasm-merge
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
| tools beyond clang and wasmtime | wasm-merge | wasm-tools, wac, the adapter | wasm-tools, wac, **wit-bindgen**, wasm-component-ld |
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
