GO_SRCS := main.go $(filter-out %_test.go, $(wildcard compile/*.go config/*.go generate/*.go internal/*/*.go merge/*.go))

.PHONY: re2test setcaps setcaps-exhaustive perftest perftest-check setperf setperf-check byteident examples clean unittest lint fmt

build: regexped

regexped: $(GO_SRCS) go.mod go.sum
	go build -o regexped .

re2test: build
	$(MAKE) -C tools/re2test test

# Set-capability coverage (plans/SETS.md §22). `setcaps` is the sampled gate
# that `re2test` already includes; `setcaps-exhaustive` is the whole-corpus
# run, measured in hours — before a release, or after touching a set emitter.
setcaps:
	$(MAKE) -C tools/re2test sets

setcaps-exhaustive:
	$(MAKE) -C tools/re2test sets-exhaustive

perftest: build
	$(MAKE) -C tools/perftest

perftest-check: build
	$(MAKE) -C tools/perftest perftest-check

setperf:
	$(MAKE) -C tools/setperf run

setperf-check:
	$(MAKE) -C tools/setperf check

# Byte-identical regression net for the single-pattern paths
# (plans/SETS.md §9.0). One fixture per code path, compared byte for byte —
# the evidence that a change to a shared emitter did not move single-pattern
# output. See compile/testdata/byteident/README.md.
byteident:
	go test ./compile -run TestByteIdentical -v

examples: build
	$(MAKE) -C examples

unittest:
	go test -gcflags=all="-N -l" -coverprofile=cover.out ./compile ./config ./generate ./merge ./internal/...
	@go tool cover -func=cover.out | grep "total:" | awk '{print "Test coverage: " $$3}'
	@rm cover.out

docker: regexped
	./get_wasm_merge.sh
	docker build -t regexped .

lint:
	golangci-lint run -D errcheck

fmt:
	gofmt -s -w .

clean:
	rm -f regexped
	$(MAKE) -C tools/re2test clean
	$(MAKE) -C tools/perftest clean
	$(MAKE) -C examples clean
