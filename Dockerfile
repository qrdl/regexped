# Prerequisites: run `make docker`, which builds regexped and puts wasm-merge,
# wasm-tools and wac in the build context first.
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
# distroless/cc includes glibc + libstdc++ required by wasm-merge
FROM gcr.io/distroless/cc-debian13 AS base

FROM scratch
LABEL org.opencontainers.image.base.name="gcr.io/distroless/cc-debian13"
COPY --from=base / /
COPY regexped   /usr/local/bin/regexped
COPY wasm-merge /usr/local/bin/wasm-merge
COPY wasm-tools /usr/local/bin/wasm-tools
COPY wac        /usr/local/bin/wac
USER nonroot
ENTRYPOINT ["/usr/local/bin/regexped"]
