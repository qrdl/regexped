GO_SRCS := main.go config/config.go \
	compile/compile.go compile/selector.go compile/engine_dfa.go \
	compile/engine_backtrack.go compile/engine_tdfa.go compile/prefix_scan.go \
	compile/wasm.go compile/mandatory_lit.go generate/generate.go \
	generate/rust_stub.go merge/merge.go internal/utils/bytes.go

.PHONY: re2test perftest examples clean unittest

build: regexped

regexped: $(GO_SRCS) go.mod go.sum
	go build -o regexped .

re2test: build
	$(MAKE) -C re2test test

perftest: build
	$(MAKE) -C perftest

examples: build
	$(MAKE) -C examples

unittest:
	go test -gcflags=all="-N -l" -coverprofile=cover.out ./compile ./config ./generate ./merge ./internal/...
	@go tool cover -func=cover.out | grep "total:" | awk '{print "Test coverage: " $$3}'
	@rm cover.out

clean:
	rm -f regexped
	$(MAKE) -C re2test clean
	$(MAKE) -C perftest clean
	$(MAKE) -C examples clean
