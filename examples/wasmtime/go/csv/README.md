# csv — CSV parsing and validation

Reads a CSV file with three columns (ID, name, email) from stdin. Uses two regexp patterns:

- **`find_csv_row`** (DFA find) — counts all rows with three columns, including those with an invalid email
- **`parse_csv_row`** (TDFA named groups) — extracts `id`, `name`, and `email` from rows that pass email validation

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
| `make compile` | compiles the patterns to `csv_regex.wasm` | `regexped` |
| `make merge` | merges the two into `final.wasm` — the same as `make` | `regexped`, Go, `wasm-merge` |
| `make run` | builds if needed, then runs `final.wasm` under wasmtime on `testdata.csv` | all of the above, plus `wasmtime` |
| `make clean` | removes the build outputs | — |

`wasm-merge` is looked up on `PATH` (a config can name it with `wasm_merge_path:` instead).

## Run

```sh
make       # build final.wasm
make run   # run it
```

Expected output of `make run`:
```
=== parse CSV (find_csv_row + parse_csv_row) ===
id=2         name=Jane "Jenny" Smith              email=jenny@test.org
id=4         name=Alice Wonderland                email=alice@company.co.uk
id="5"       name=Carol Brown                     email=carol@somewhere.net

6 rows total, 4 valid, 2 with invalid email
```

## Build pipeline

```
regexped generate      →  generate Go stub (//go:wasmimport)
go build (GOOS=wasip1) →  compile Go to WASM
regexped compile       →  compile regexp patterns to WASM
regexped merge         →  merge Go WASM + regexp WASM into final binary
wasmtime               →  execute
```
