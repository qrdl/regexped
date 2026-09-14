# sql-injection — SQL injection detection

Detects SQL injection patterns in input strings using the **Backtracking engine** (forced via `max_dfa_states: 1`). Demonstrates all three capture modes on the same pattern: anchored match, find, and named groups.

Named groups extracted: `type` (attack type), `payload` (remainder of the matched line).

## Prerequisites

The Makefile installs nothing. Install these first:

| Tool | How to install |
|---|---|
| `regexped` | run `make` in the repo root |
| Go 1.23+ | [go.dev/dl](https://go.dev/dl/) |
| `wasm-merge` | from [Binaryen](https://github.com/WebAssembly/binaryen/releases): unpack a release and put its `bin/` on `PATH` |
| `wasmtime` | `curl https://wasmtime.dev/install.sh -sSf \| bash` — see [wasmtime.dev](https://wasmtime.dev) |

What each target needs:

| Target | What it does | Needs |
|---|---|---|
| `make` | builds `final.wasm` — the steps below | `regexped`, Go, `wasm-merge` |
| `make generate` | generates the Go stub `stub.go` | `regexped` |
| `make build` | generates the stub if needed, then `GOOS=wasip1 GOARCH=wasm go build` into `app.wasm` | `regexped`, Go |
| `make compile` | compiles the patterns to `sqli.wasm` | `regexped` |
| `make merge` | merges the two into `final.wasm` — the same as `make` | `regexped`, Go, `wasm-merge` |
| `make run` | builds if needed, then runs `final.wasm` under wasmtime | all of the above, plus `wasmtime` |
| `make clean` | removes the build outputs | — |

`wasm-merge` is looked up on `PATH` (a config can name it with `wasm_merge_path:` instead).

## Run

```sh
make       # build final.wasm
make run   # run it
```

## Build pipeline

```
regexped generate      →  generate Go stub (//go:wasmimport)
go build (GOOS=wasip1) →  compile Go to WASM
regexped compile       →  compile regexp pattern to WASM
regexped merge         →  merge Go WASM + regexp WASM into final binary
wasmtime               →  execute
```
