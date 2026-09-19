# Using Regexped via Docker

The regexped Docker image contains the `regexped` compiler and the three external tools it shells out to: `wasm-merge` (from Binaryen), `wasm-tools` and `wac` (both from the Bytecode Alliance). It is intended to be used as a command-line tool against a project directory mounted as a volume.

## Official image

The official image is published on Docker Hub as [`qrdl/regexped`](https://hub.docker.com/r/qrdl/regexped):

```bash
docker pull qrdl/regexped
```

It is built for **`linux/amd64` and `linux/arm64`**, so it runs natively on
Intel and AMD machines, on Apple Silicon under Docker Desktop, and on arm64
servers. `docker pull` picks the right one; nothing needs to be said on the
command line.

## Building the image locally

```bash
make docker
```

This builds the `regexped` binary locally and assembles the build context in `docker/` — the binary is built there and `wasm-merge`, `wasm-tools` and `wac` are downloaded there (each one's latest release, if it is not already present — never copied from your `PATH`, which may be linked against a different glibc than the image carries). It then builds the Docker image tagged `regexped` from that directory.

Every binary in that directory carries its architecture in its name —
`regexped-arm64`, `wasm-merge-arm64` and so on — and the `Dockerfile` picks a
set with `TARGETARCH`. That is what lets the published image be built for both
architectures at once: one `docker buildx` build shares a single context
between its two per-architecture builds, so both sets have to be present under
distinct names.

`make docker` assembles only your own machine's set, which is all a local image
needs. To build for the other one instead:

```bash
make docker DOCKER_ARCH=arm64
```

Everything the image needs lives in [`docker/`](../docker): the `Dockerfile`, the three `get_*.sh` fetch scripts, the `arch.sh` helper they share, and the binaries they assemble.

## General usage

Mount your project directory to `/work` and pass `regexped` commands as arguments:

```bash
docker run --rm -v /path/to/your/project:/work -w /work regexped \
  <command> [flags]
```

All paths in `regexped.yaml` are resolved relative to the config file, which in turn resolves relative to `/work` inside the container. Keep all input and output files inside the mounted directory.

## File ownership

**You do not need `--user`.** Everything regexped writes into the mounted
directory — compiled WASM, generated stubs, a component's sibling `.wit`, a
merged binary, `--diag-json` output — is handed to the user who owns the
directory it lands in, and so are any directories regexped had to create along
the way (`stub_file: src/generated/stubs.rs` creates `src/` and `src/generated/`
owned by you, not by root).

The container runs as root because it has to: your project directory belongs to
you, the kernel enforces that ownership inside the container, and a non-root
container cannot create a single file in it. Root can write, and regexped then
corrects the ownership of what it produced.

Passing `--user $(id -u):$(id -g)` anyway is still supported and still works —
regexped sees a non-root uid and leaves ownership alone, which is the correct
answer, because files created by that uid already belong to you.

Two cases where the correction cannot apply, neither of them a failure:

- **Docker Desktop on macOS and Windows** synthesises ownership on bind mounts.
  Files already appear as yours; `chown` is a no-op or is refused, and regexped
  logs a warning at most.
- **Rootless Docker and Podman** already map the container's root to your own
  uid, so the outputs are yours before regexped looks at them.

A failed correction is always a warning, never an error: the output itself is
correct, and a build must not fail over the ownership bit on a file you can
already read.

---

## Generating stubs

```bash
docker run --rm -v /path/to/your/project:/work -w /work regexped \
  generate --config=regexped.yaml
```

Reads `regexped.yaml`, writes the stub file to the path specified by `stub_file` in the config (e.g. `src/stubs.rs`, `stubs.js`, `stubs.go`, `stubs.h`). The stub type is inferred from the file extension or the `stub_type` config field.

Under `wasm_format: component` only three stub types exist: `rust`, `c` and `wit`. The C component stub also writes a `wit/` directory beside the header, which `wasm-tools component embed` needs when you wrap your guest. See [component.md](component.md).

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

Compiles all regexp patterns in the config to a single WASM file at the path specified by `wasm_file` in the config.

- If the config has no `output` field, the module is **standalone** (owns its memory; load directly in JS/TS without merging).
- If the config has an `output` field, the module is **embedded** (imports memory from `"main"`; must be merged with a host binary).
- Under `wasm_format: component` the output is a **component**, which always owns its memory: `output` only names what `regexped merge` writes. `compile` also writes a sibling `.wit` file — the interface a consumer binds against — next to `wasm_file`, and uses `wasm-tools`, which the image includes, to wrap the core module into the component.

---

## Merging WASM modules

```bash
docker run --rm -v /path/to/your/project:/work -w /work regexped \
  merge --config=regexped.yaml --main=target/wasm32-wasip1/release/app.wasm regexps.wasm
```

Links the host main WASM with one or more regexp WASM artifacts into a single binary. The output path is taken from the `output` field in the config, or overridden with `--output`. The command dispatches on `wasm_format`: a module config is merged with `wasm-merge`, a component config is composed with `wac plug`.

All three tools are available in `$PATH` inside the container — no extra configuration needed:

| Tool | Used for |
|---|---|
| `wasm-merge` | `regexped merge` under `wasm_format: module` |
| `wasm-tools` | `wasm_format: component` — `regexped compile` wraps the core module into a component with it, and `regexped merge` checks each component's exports with it before composing |
| `wac` | `regexped merge` under `wasm_format: component` |

An image missing any of them could only do part of the job.

---

## Typical workflows

### Rust

```bash
# 1. Generate Rust stubs
docker run --rm -v $(pwd):/work -w /work regexped \
  generate --config=regexped.yaml

# 2. Build your Rust project to WASM (outside the container — needs cargo)
cargo build --target wasm32-wasip1 --release

# 3. Compile regexp patterns to WASM
docker run --rm -v $(pwd):/work -w /work regexped \
  compile --config=regexped.yaml

# 4. Merge into a single binary
docker run --rm -v $(pwd):/work -w /work regexped \
  merge --config=regexped.yaml --main=target/wasm32-wasip1/release/app.wasm regexps.wasm
```

### Go

```bash
# 1. Generate Go stubs
docker run --rm -v $(pwd):/work -w /work regexped \
  generate --config=regexped.yaml

# 2. Compile regexp patterns to WASM
docker run --rm -v $(pwd):/work -w /work regexped \
  compile --config=regexped.yaml

# 3. Build your Go project to WASM (outside the container — needs Go)
GOOS=wasip1 GOARCH=wasm go build -o app.wasm .

# 4. Merge into a single binary
docker run --rm -v $(pwd):/work -w /work regexped \
  merge --config=regexped.yaml --main=app.wasm regexps.wasm
```

### Rust, as a component

The config sets `wasm_format: component` (and a `wit_package`). The guest is a
wasip2 component, and `merge` composes it with the regexp component using `wac`:

```bash
# 1. Generate the Rust component stub
docker run --rm -v $(pwd):/work -w /work regexped \
  generate --config=regexped.yaml

# 2. Build your Rust project as a component (outside the container — needs cargo
#    and the wasm32-wasip2 target; the stub needs the wit-bindgen crate)
cargo build --target wasm32-wasip2 --release

# 3. Compile regexp patterns to a component plus its sibling .wit
docker run --rm -v $(pwd):/work -w /work regexped \
  compile --config=regexped.yaml

# 4. Compose the two into one component (wac)
docker run --rm -v $(pwd):/work -w /work regexped \
  merge --config=regexped.yaml --main=target/wasm32-wasip2/release/app.wasm regexps.wasm

# 5. Run it (outside the container)
wasmtime run composed.wasm
```

Use the file names your config's `wasm_file` and `output` give. See
[component.md](component.md) for the C route and for binding the `.wit` directly.

### JavaScript / TypeScript (no merge needed)

```bash
# 1. Compile regexp patterns to WASM (standalone mode — no output field in config)
docker run --rm -v $(pwd):/work -w /work regexped \
  compile --config=regexped.yaml

# 2. Generate JS/TS stub
docker run --rm -v $(pwd):/work -w /work regexped \
  generate --config=regexped.yaml
```

Load the compiled WASM directly in your JS/TS code:

```js
await init(await fetch('./regexps.wasm').then(r => r.arrayBuffer()));
```
