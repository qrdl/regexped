# inject-scanner — injection payload scanning with two pattern sets

Scans HTTP request payloads for SQL injection and XSS threats using **two
independent pattern sets** compiled into a single WASM module.

- **Set `sqli`** (`scan_sqli`): UNION SELECT, DROP TABLE, OR tautology, SLEEP injection
- **Set `xss`** (`scan_xss`): `<script` tag, `javascript:` protocol, `onerror=` handler, `alert()` call

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
| `make compile` | compiles both pattern sets to `threats.wasm` | `regexped` |
| `make merge` | merges `main.wasm` and `threats.wasm` into `final.wasm` — the same as `make` | `regexped`, AssemblyScript, `wasm-merge` |
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
[normal] payload: SELECT name FROM users WHERE id = 42
  [SQLI] clean
  [XSS]  clean
[sqli] payload: GET /api?id=1 UNION SELECT * FROM passwords
  [SQLI] union_select
  [XSS]  clean
[xss] payload: POST /comment body=<script>alert(1)</script>
  [SQLI] clean
  [XSS]  detected: alert_call
[both] payload: GET /search?q=<script>x</script>&id=1 UNION SELECT 1
  [SQLI] union_select
  [XSS]  detected: script_tag
[clean] payload: GET /index.html HTTP/1.1
  [SQLI] clean
  [XSS]  clean
[union-no-sel] payload: The UNION of two sets is not always a SELECT operation
  [SQLI] clean
  [XSS]  clean
[drop-table] payload: DROP TABLE users; -- dangerous DDL injection
  [SQLI] drop_table
  [XSS]  clean
```

## Build pipeline

```
regexped generate   →  generate the AssemblyScript stub (stub.ts)
asc                 →  compile index.ts to WASM (main.wasm)
regexped compile    →  compile both pattern sets to WASM (threats.wasm)
regexped merge      →  merge main.wasm + threats.wasm → final.wasm
wasmtime run        →  execute (make run)
```
