# node — domain extraction from URLs

Reads text from stdin and prints the domain of every URL found, one per line. Uses **TDFA named groups** to extract just the `host` capture group.

## Prerequisites

- `regexped` binary (run `make` in the repo root)
- Node.js 22+ (for `--experimental-strip-types`) or `tsx` (`npm install -g tsx`)

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
regexped compile    →  compile regex pattern to WASM
regexped generate   →  generate TypeScript ES module stub
```
