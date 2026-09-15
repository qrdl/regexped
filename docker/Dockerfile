# Prerequisites: run `make docker`, which copies the regexped binary and fetches
# wasm-merge, wasm-tools and wac into THIS directory — the build context is
# docker/, not the repo root, so the context is these four binaries and nothing
# else.
#
# All three tools are shelled out to by the compiler, so an image without them
# can only do part of the job:
#
#   wasm-merge   `regexped merge` for wasm_format: module
#   wasm-tools   wasm_format: component — wraps the core module into a component
#   wac          `regexped merge` for wasm_format: component — composition is
#                what merging is for components, and merge dispatches on the
#                configured format
#
# RUNS AS ROOT, DELIBERATELY. The image is a command-line tool pointed at a
# bind-mounted project directory, which belongs to the host user, and the kernel
# enforces that ownership inside the container: as `nonroot` (uid 65532) every
# write into /work fails outright with EACCES, which is why every example in
# docs/docker.md used to carry --user $(id -u):$(id -g). Root can write, and
# regexped then hands each file it produces to the owner of the directory it
# landed in (internal/ownership), so the outputs belong to the invoking user
# without the flag. Passing --user anyway still works and is still supported:
# the correction sees a non-root uid and does nothing.
#
# distroless/cc includes glibc + libstdc++ required by wasm-merge
FROM gcr.io/distroless/cc-debian13 AS base

FROM scratch
LABEL org.opencontainers.image.base.name="gcr.io/distroless/cc-debian13"
COPY --from=base / /
COPY regexped   /usr/local/bin/regexped
COPY wasm-merge /usr/local/bin/wasm-merge
COPY wasm-tools /usr/local/bin/wasm-tools
COPY wac        /usr/local/bin/wac
ENTRYPOINT ["/usr/local/bin/regexped"]
