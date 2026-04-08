# Prerequisites: run `make docker` which builds regexped and downloads wasm-merge locally first
# distroless/cc includes glibc + libstdc++ required by wasm-merge
FROM gcr.io/distroless/cc-debian13
COPY regexped   /usr/local/bin/regexped
COPY wasm-merge /usr/local/bin/wasm-merge
ENTRYPOINT ["/usr/local/bin/regexped"]
