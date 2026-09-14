# find-email — email extraction with AssemblyScript

Finds all email addresses in strings and parses each into `user` and `domain` named capture groups using the **TDFA engine**.

## Prerequisites

The Makefile installs nothing. Install these first:

| Tool | How to install |
|---|---|
| `regexped` | run `make` in the repo root |
| [Node.js](https://nodejs.org) 16+ with npm 7+ | from nodejs.org or your OS package manager — AssemblyScript's minimum |
| AssemblyScript and its WASI shim | `npm install` in **this directory**. It installs the two dev dependencies in `package.json` into `node_modules`. It has to be this directory, not a global install: `asconfig.json` extends the shim from `node_modules` |
| `wasm-merge` | from [Binaryen](https://github.com/WebAssembly/binaryen/releases): unpack a release and put its `bin/` on `PATH` |
| `wasmtime` | `curl https://wasmtime.dev/install.sh -sSf \| bash` — see [wasmtime.dev](https://wasmtime.dev) |

What each target needs:

| Target | What it does | Needs |
|---|---|---|
| `make` | builds `final.wasm` — the four steps below | `regexped`, AssemblyScript, `wasm-merge` |
| `make generate` | generates the stub `stub.ts` | `regexped` |
| `make build` | compiles `index.ts` to `main.wasm` with `asc`; stops with a message if AssemblyScript or the shim is missing | `regexped`, AssemblyScript |
| `make compile` | compiles the pattern to `email.wasm` | `regexped` |
| `make merge` | merges `main.wasm` and `email.wasm` into `final.wasm` — the same as `make` | `regexped`, AssemblyScript, `wasm-merge` |
| `make run` | builds `final.wasm` if needed, then runs it | all of the above, plus `wasmtime` |
| `make clean` | removes the build outputs; leaves `node_modules` alone | — |

`wasm-merge` is looked up on `PATH` (a config can name it with `wasm_merge_path:` instead). Set `ASC=/path/to/asc` to use a different AssemblyScript compiler.

## Run

```sh
npm install   # once
make          # build final.wasm
make run      # run it
```

Expected output of `make run`:
```
input: Contact alice@example.com or bob@company.org for details.
  email:  alice@example.com
    user:   alice
    domain: example.com
  email:  bob@company.org
    user:   bob
    domain: company.org
input: reach us at support@open-source.io and sales@widgets.co.uk
  email:  support@open-source.io
    user:   support
    domain: open-source.io
  email:  sales@widgets.co.uk
    user:   sales
    domain: widgets.co.uk
input: no emails here
  (no emails found)
```

## Build pipeline

```
regexped generate   →  generate the AssemblyScript stub (stub.ts)
asc                 →  compile index.ts to WASM (main.wasm)
regexped compile    →  compile the pattern to WASM (email.wasm)
regexped merge      →  merge main.wasm + email.wasm → final.wasm
wasmtime run        →  execute (make run)
```

## AS stub API

The generated `stub.ts` exports a single stateless function:

```ts
export function find_email(input: ArrayBuffer, offset: i32): i32
```

Scans `input[offset..]` for the next match. Returns the **`dataStart`** pointer of a
static `Int32Array` slot buffer on match, or `0` if no match is found.

Slot layout (each value is an absolute byte offset into `input`):

| Slot index | Meaning |
|---|---|
| 0, 1 | full match start, end |
| 2, 3 | `user` group start, end |
| 4, 5 | `domain` group start, end |

Read slots with `load<i32>(slots + i * 4)`. The buffer is **static** — copy values
before the next call. An unmatched optional group has both slots set to `-1`.

Advance `offset` to `matchEnd` (or `matchStart + 1` for zero-length matches) to
iterate all non-overlapping matches.
