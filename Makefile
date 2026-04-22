GO_SRCS := main.go $(filter-out %_test.go, $(wildcard compile/*.go config/*.go generate/*.go internal/*/*.go merge/*.go))

.PHONY: re2test perftest examples clean unittest lint fmt

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

docker: regexped
	./get_wasm_merge.sh
	docker build -t regexped .

lint:
	golangci-lint run -D errcheck

fmt:
	gofmt -s -w .

clean:
	rm -f regexped
	$(MAKE) -C re2test clean
	$(MAKE) -C perftest clean
	$(MAKE) -C examples clean
