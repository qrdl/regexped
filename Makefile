.PHONY: build re2test perftest clean

build:
	go build -o regexped .

re2test: build
	cd re2_test && go run . re2-exhaustive.txt

perftest: build
	cd perf_test && go run .

clean:
	rm -f regexped re2_test/re2test
	cd perf_test && $(MAKE) clean
