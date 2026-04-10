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

The generated `assembly/stub.ts` exports:

| Function | Description |
|---|---|
| `find_email_reset()` | Reset iterator before scanning a new input |
| `find_email_next(buf: ArrayBuffer): bool` | Advance to the next match; returns false when exhausted |
| `find_email_group(i: i32): i64` | Packed `(start << 32 \| end)` for group i (0 = full match), or -1 |
| `find_email_get_user(): i64` | Packed `(start << 32 \| end)` for the `user` group, or -1 |
| `find_email_get_domain(): i64` | Packed `(start << 32 \| end)` for the `domain` group, or -1 |

Positions are byte offsets into the `ArrayBuffer` passed to `find_email_next`.
Use `String.UTF8.decodeUnsafe(ptr + start, end - start, false)` to extract substrings.
