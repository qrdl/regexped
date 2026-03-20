.PHONY: re2test perftest examples clean

build: regexped

regexped:
	go build -o regexped .

re2test: build
	$(MAKE) -C re2test test

perftest: build
	$(MAKE) -C perftest

examples: build
	$(MAKE) -C examples

clean:
	rm -f regexped
	$(MAKE) -C re2test clean
	$(MAKE) -C perftest clean
	$(MAKE) -C examples clean
