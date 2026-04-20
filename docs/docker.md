# Using Regexped via Docker

The regexped Docker image contains the `regexped` compiler and `wasm-merge` (from Binaryen). It is intended to be used as a command-line tool against a project directory mounted as a volume.

## Official image

The official image is published on Docker Hub as [`qrdl/regexped`](https://hub.docker.com/r/qrdl/regexped):

```bash
docker pull qrdl/regexped
```

## Building the image locally

```bash
make docker
```

This builds the `regexped` binary locally, downloads `wasm-merge` if not already present, then builds the Docker image tagged `regexped`.

## General usage

Mount your project directory to `/work` and pass `regexped` commands as arguments:

```bash
docker run --rm -v /path/to/your/project:/work -w /work regexped <command> [flags]
```

All paths in `regexped.yaml` are resolved relative to the config file, which in turn resolves relative to `/work` inside the container. Keep all input and output files inside the mounted directory.

---

## Generating stubs

```bash
docker run --rm -v /path/to/your/project:/work -w /work regexped \
  generate --config=regexped.yaml
```

Reads `regexped.yaml`, writes the stub file to the path specified by `stub_file` in the config (e.g. `src/stubs.rs`, `stubs.js`, `stubs.go`, `stubs.h`). The stub type is inferred from the file extension or the `stub_type` config field.

To write the stub to stdout:

```bash
docker run --rm -v /path/to/your/project:/work -w /work regexped \
  generate --config=regexped.yaml --output=-
```

---

## Compiling patterns to WASM

```bash
docker run --rm -v /path/to/your/project:/work -w /work regexped \
  compile --config=regexped.yaml
```

Compiles all regex patterns in the config to a single WASM file at the path specified by `wasm_file` in the config.

- If the config has no `output` field, the module is **standalone** (owns its memory; load directly in JS/TS without merging).
- If the config has an `output` field, the module is **embedded** (imports memory from `"main"`; must be merged with a host binary).

---

## Merging WASM modules

```bash
docker run --rm -v /path/to/your/project:/work -w /work regexped \
  merge --config=regexped.yaml --main=target/wasm32-wasip1/release/app.wasm regexps.wasm
```

Merges the host main WASM with one or more regex WASM modules into a single binary. The output path is taken from the `output` field in the config, or overridden with `--output`.

`wasm-merge` is available in `$PATH` inside the container — no extra configuration needed.

---

## Typical workflows

### Rust

```bash
# 1. Generate Rust stubs
docker run --rm -v $(pwd):/work -w /work regexped generate --config=regexped.yaml

# 2. Build your Rust project to WASM (outside the container — needs cargo)
cargo build --target wasm32-wasip1 --release

# 3. Compile regex patterns to WASM
docker run --rm -v $(pwd):/work -w /work regexped compile --config=regexped.yaml

# 4. Merge into a single binary
docker run --rm -v $(pwd):/work -w /work regexped \
  merge --config=regexped.yaml --main=target/wasm32-wasip1/release/app.wasm regexps.wasm
```

### Go

```bash
# 1. Generate Go stubs
docker run --rm -v $(pwd):/work -w /work regexped generate --config=regexped.yaml

# 2. Compile regex patterns to WASM
docker run --rm -v $(pwd):/work -w /work regexped compile --config=regexped.yaml

# 3. Build your Go project to WASM (outside the container — needs Go)
GOOS=wasip1 GOARCH=wasm go build -o app.wasm .

# 4. Merge into a single binary
docker run --rm -v $(pwd):/work -w /work regexped \
  merge --config=regexped.yaml --main=app.wasm regexps.wasm
```

### JavaScript / TypeScript (no merge needed)

```bash
# 1. Compile regex patterns to WASM (standalone mode — no output field in config)
docker run --rm -v $(pwd):/work -w /work regexped compile --config=regexped.yaml

# 2. Generate JS/TS stub
docker run --rm -v $(pwd):/work -w /work regexped generate --config=regexped.yaml
```

Load the compiled WASM directly in your JS/TS code:

```js
await init(await fetch('./regexps.wasm').then(r => r.arrayBuffer()));
```
