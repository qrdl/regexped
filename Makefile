# Recipes run under bash with pipefail. Two coverage targets below pipe
# `go test` into `grep` for readability, and a pipeline's status is its LAST
# command's: `FAIL` is in both filters, so a failing test printed FAIL, grep
# matched it and exited 0, and the gate reported success on failure. That is
# the worst way for a coverage gate to break, since it breaks silently and in
# the passing direction.
SHELL := /bin/bash
.SHELLFLAGS := -o pipefail -c

GO_SRCS := main.go $(filter-out %_test.go, $(wildcard compile/*.go config/*.go generate/*.go internal/*/*.go merge/*.go))

.PHONY: from-coverage set-coverage re2test setcaps setcaps-likely setcaps-exhaustive perftest perftest-check setperf setperf-check setperf-fuel-cross byteident examples clean unittest lint fmt

build: regexped

regexped: $(GO_SRCS) go.mod go.sum
	go build -o regexped .

re2test: build
	$(MAKE) -C tools/re2test test

# Set-capability coverage. `setcaps` is the sampled gate
# that `re2test` already includes; `setcaps-exhaustive` is the whole-corpus
# run, measured in hours — before a release, or after touching a set emitter.
setcaps:
	$(MAKE) -C tools/re2test sets

# The same capability coverage under a non-neutral set-level hint, which
# `setcaps` never applies — see tools/re2test/Makefile's `sets-likely`.
setcaps-likely:
	$(MAKE) -C tools/re2test sets-likely

setcaps-exhaustive:
	$(MAKE) -C tools/re2test sets-exhaustive

# Emitter reach for the find/groups property sweeps.
#
# The sweeps assert that every exported find/groups answer matches Go at every
# `from`; this target additionally proves WHICH emitters they reach, from the
# coverage profile of that same run. Two facts, one execution — a second corpus
# would drift, and the drift is what let plans/FUZZER_BUGS.md 65 ship: the sweep
# passed for weeks over shapes reaching eight of fourteen find emitters, and two
# of the six it missed were broken.
#
# Kept out of `go test ./...` because it needs two steps; the check skips
# without REGEXPED_COVERPROFILE, so the plain test run stays self-contained.
FROM_COVERPROFILE := $(CURDIR)/tools/fuzz/from-coverage.out

from-coverage:
	cd tools/fuzz && go test -run 'TestFindFrom|TestGroupsFrom' \
		-coverpkg=github.com/qrdl/regexped/compile \
		-coverprofile=$(FROM_COVERPROFILE) ./...
	cd tools/fuzz && REGEXPED_COVERPROFILE=$(FROM_COVERPROFILE) \
		go test -run TestEveryEmitterIsReachedBySweeps -v ./... | grep -E 'emitters|FAIL|ok'
	@rm -f $(FROM_COVERPROFILE)

# Set-emitter reach. Same question as from-coverage, for compile/set_*.go:
# which emitters do the tests that CHECK ANSWERS actually drive? The smoke
# matrix in compile/set_matrix_coverage_test.go proves a shape still COMPILES,
# which is a different claim — see that file's opening comment for the gap it
# describes, and this target for the other side of it.
#
# Runs the whole tools/fuzz suite (~5 min), because the set targets are spread
# across it rather than named by one pattern.
SET_COVERPROFILE := $(CURDIR)/tools/fuzz/set-coverage.out

set-coverage:
	cd tools/fuzz && go test -coverpkg=github.com/qrdl/regexped/compile \
		-coverprofile=$(SET_COVERPROFILE) ./...
	cd tools/fuzz && REGEXPED_SETCOVERPROFILE=$(SET_COVERPROFILE) \
		go test -run TestEverySetEmitterIsReached -v ./... | grep -E 'set emitters|never reached|^ +[a-z]|FAIL|ok'
	@rm -f $(SET_COVERPROFILE)

perftest: build
	$(MAKE) -C tools/perftest

perftest-check: build
	$(MAKE) -C tools/perftest perftest-check

setperf:
	$(MAKE) -C tools/setperf run

setperf-check:
	$(MAKE) -C tools/setperf check

# Cross-engine FUEL: ours vs regex-automata's, both metered over one
# whole-input operation. Deterministic and machine-independent — the number to
# quote when wall-clock would only report this machine's placement noise.
setperf-fuel-cross:
	$(MAKE) -C tools/setperf fuel-cross

# Byte-identical regression net for the single-pattern paths: one fixture
# per code path, compared byte for byte —
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
