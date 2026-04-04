# csv — CSV parsing and validation

Reads a CSV file with three columns (ID, name, email) from stdin. Uses two regex patterns:

- **`find_csv_row`** (DFA find) — counts all rows with three columns, including those with an invalid email
- **`parse_csv_row`** (TDFA named groups) — extracts `id`, `name`, and `email` from rows that pass email validation

## Prerequisites

- `regexped` binary (run `make` in the repo root)
- Go 1.23+
- [wasm-merge](https://github.com/WebAssembly/binaryen)
- [wasmtime](https://wasmtime.dev)

## Run

```sh
make
```

Expected output:
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
regexped compile       →  compile regex patterns to WASM
regexped merge         →  merge Go WASM + regex WASM into final binary
wasmtime               →  execute
```
