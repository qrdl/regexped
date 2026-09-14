# node — domain extraction from URLs

Reads text from stdin and prints the domain of every URL found, one per line. Uses **TDFA named groups** to extract just the `host` capture group.

See [docs/node.md](../../docs/node.md) for the full guide.

## Prerequisites

The Makefile installs nothing. Install these first:

| Tool | How to install |
|---|---|
| `regexped` | run `make` in the repo root |
| [Node.js](https://nodejs.org) with `npm` | from nodejs.org or your OS package manager |
| TypeScript's `tsc` | `npm install -g typescript` |
| Node type definitions | `npm install -g @types/node` |

What each target needs:

| Target | What it does | Needs |
|---|---|---|
| `make` | compiles the patterns, generates `regexp.ts`, then type-checks and compiles to `dist/` with `tsc` | `regexped`, `tsc`, the type definitions, and `npm` (used only to locate them) |
| `make run` | builds if needed, then runs `node dist/main.js` on sample input | the above, plus Node.js |
| `make clean` | removes the build outputs | — |

`make` checks for `tsc` and the type definitions (and for `npm`, which it uses to
find them) before compiling, and says which one is missing. Point it elsewhere
with `make TSC=/path/to/tsc NODE_TYPE_ROOTS=/path/to/@types`.

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
