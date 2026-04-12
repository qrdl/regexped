# find-email — email extraction with AssemblyScript

Finds all email addresses in strings and parses each into `user` and `domain` named capture groups using the **TDFA engine**.

## Prerequisites

- `regexped` binary (run `make` in the repo root)
- [Node.js](https://nodejs.org) 18+ (for `npx asc`)
- [wasm-merge](https://github.com/WebAssembly/binaryen)
- [wasmtime](https://wasmtime.dev)

AssemblyScript (`asc`) and the WASI shim are installed locally via `npm install` on first build — no global install needed.

## Run

```sh
make
```

Expected output:
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
regexped generate   →  generate AS stub (stub.ts)
npx asc             →  compile AssemblyScript to WASM (main.wasm)
regexped compile    →  compile regex pattern to WASM (email.wasm)
regexped merge      →  merge main.wasm + email.wasm → final.wasm
wasmtime run        →  execute
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
