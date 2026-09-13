# node — domain extraction from URLs

Reads text from stdin and prints the domain of every URL found, one per line. Uses **TDFA named groups** to extract just the `host` capture group.

See [docs/node.md](../../docs/node.md) for the full guide.

## Prerequisites

- `regexped` binary (run `make` in the repo root)
- TypeScript's `tsc` on `PATH` (`npm install -g typescript`)
- Node type definitions, installed globally (`npm install -g @types/node`)
- Node.js, to run the compiled JavaScript

`make run` checks for `tsc` and the type definitions (and for `npm`, which it uses
to find them) before compiling, and says which one is missing. Point it elsewhere
with `make run TSC=/path/to/tsc NODE_TYPE_ROOTS=/path/to/@types`.

## Run

```sh
make run
```

Expected output:
```
example.com
foo.org
```

## Build pipeline

```
regexped compile    →  compile regexp pattern to WASM
regexped generate   →  generate TypeScript ES module stub
tsc                 →  type-check (strict) and compile main.ts and the stub to dist/
node dist/main.js   →  run
```
