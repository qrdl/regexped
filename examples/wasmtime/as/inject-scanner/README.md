# wasmtime/as/inject-scanner — Injections payload scanner with two pattern sets

Scans HTTP request payloads for SQL injection and XSS threats using **two
independent pattern sets** compiled into a single WASM module.

- **Set `sqli`** (`scan_sqli`): UNION SELECT, DROP TABLE, OR tautology, SLEEP injection
- **Set `xss`** (`scan_xss`): `<script` tag, `javascript:` protocol, `onerror=` handler, `alert()` call

## Prerequisites

- `regexped` binary (run `make` in the repo root)
- AssemblyScript compiler: `npm install` (in this directory)
- `wasm-merge` from [Binaryen](https://github.com/WebAssembly/binaryen)
- `wasmtime` CLI

## Run

```sh
make
```

Expected output (last payload):
```
payload: DROP TABLE users; -- dangerous DDL injection
  [SQLI] drop_table at 0..10
  [XSS]  clean
```

## Build pipeline

```
regexped compile   →  compile 2-set, 8-pattern module to WASM
regexped generate  →  generate AssemblyScript stub
asc                →  compile AS app to WASM
regexped merge     →  merge app + patterns into final.wasm
wasmtime run       →  execute
```
