# Prerequisites: run `make docker`, which builds regexped and puts wasm-merge and
# wasm-tools in the build context first.
#
# Both tools are shelled out to by the compiler, so an image without them can
# only do part of the job: wasm-merge for `regexped merge`, wasm-tools for
# `wasm_format: component` (it wraps the core module into a component).
#
# distroless/cc includes glibc + libstdc++ required by wasm-merge
FROM gcr.io/distroless/cc-debian13 AS base

FROM scratch
LABEL org.opencontainers.image.base.name="gcr.io/distroless/cc-debian13"
COPY --from=base / /
COPY regexped   /usr/local/bin/regexped
COPY wasm-merge /usr/local/bin/wasm-merge
COPY wasm-tools /usr/local/bin/wasm-tools
USER nonroot
ENTRYPOINT ["/usr/local/bin/regexped"]
